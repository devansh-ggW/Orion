const fs = require('fs');
const vm = require('vm');
const path = require('path');
const root = path.resolve(__dirname, '..');
const context = { window:{}, console, setTimeout, queueMicrotask };
vm.createContext(context);
for (const file of ['knowledge.js','engine.js']) {
  vm.runInContext(fs.readFileSync(path.join(root,file),'utf8'), context, {filename:file});
}
const E = context.window.OrionEngine;
function assert(ok,msg){ if(!ok) throw new Error(msg); }
(async()=>{
  assert(E.RULES.length===150, `Expected 150 rules, got ${E.RULES.length}`);
  const intel=E.buildProjectIntelligence(E.makeTestProject());
  assert(intel.trustSources.length>0, 'Project intelligence should identify trust-boundary sources');
  assert(intel.safeBoundaries.length>=0, 'Project intelligence safe-boundary list should exist');
  const bad = E.makeTestProject();
  const badResult = await E.scan(bad,()=>{});
  const badIds = new Set(badResult.findings.map(f=>f.id));
  assert(badIds.has('DOM-XSS-002'), 'Expected DOM source-to-sink finding');
  assert(badIds.has('INJECT-SQL-001'), 'Expected SQL interpolation finding');
  assert(badIds.has('COOKIE-001'), 'Expected cookie hardening finding');
  assert(!badResult.findings.some(f=>f.id==='UPLOAD-001'), 'Toy fixture should not create an upload finding without upload code');
  assert(badResult.findings.filter(f=>f.id==='HTML-003').every(f=>f.advisory), 'HTML-003 must be an advisory');
  assert(badResult.findings.filter(f=>f.id.startsWith('HEADERS-')||f.id==='HEADER-CTO-001').every(f=>f.advisory), 'Header source-only checks must be advisories');
  const validatedUpload = [{path:'server.py',name:'server.py',text:"def upload(req):\n    ext = Path(req.file.filename).suffix.lower()\n    if ext not in {'.mp4','.webm'}: raise ValueError('Unsupported video format')\n    safe = secure_filename(req.file.filename)\n    path = UPLOAD_DIR / (uuid.uuid4().hex + ext)\n    path.write_bytes(req.file.file.read())\n"}];
  const uploadResult = await E.scan(validatedUpload,()=>{});
  assert(!uploadResult.findings.some(f=>f.id==='UPLOAD-001'), 'Validated upload fixture should not be flagged as missing a type boundary');
  assert(!uploadResult.findings.some(f=>f.id==='PATH-002'), 'Sanitized filename + generated storage name should not be flagged');
  const safe = [
    {path:'src/app.js',name:'app.js',text:"const clean = document.querySelector('#name'); clean.textContent = new URLSearchParams(location.search).get('name') || '';"},
    {path:'server.py',name:'server.py',text:"def save(upload):\n    ext = Path(upload.filename).suffix.lower()\n    if ext not in {'.mp4','.webm'}: raise ValueError('bad type')\n    safe = secure_filename(upload.filename)\n    path = UPLOAD_DIR / (uuid.uuid4().hex + ext)\n    path.write_bytes(upload.file.read(3_000_000))\n"},
    {path:'deploy.conf',name:'deploy.conf',text:'Content-Security-Policy: default-src \'self\'\nReferrer-Policy: strict-origin-when-cross-origin\nX-Content-Type-Options: nosniff\n'},
  ];
  const safeResult = await E.scan(safe,()=>{});
  assert(safeResult.findings.length===0, `Safe fixture should have 0 findings, got ${safeResult.findings.length}`);
  const prompt = badResult.prompt;
  assert(prompt.includes('PLAIN-ENGLISH PROBLEM:'), 'Prompt must be dynamically compiled from findings');
  assert(prompt.includes('REVIEW ITEMS — NOT CONFIRMED VULNERABILITIES'), 'Prompt must separate advisory review items');
  assert(prompt.includes('VERIFY:'), 'Prompt must contain per-finding verification guidance');
  assert(prompt.includes('ORION REASONING SNAPSHOT'), 'Prompt must include project reasoning context');
  assert(prompt.includes('EVIDENCE TIER:'), 'Prompt must include evidence tier for each issue');

  const advanced = [
    {path:'server.js',name:'server.js',text:`app.get('/users/:id',(req,res)=>db.findById(req.params.id));`},
    {path:'reset.js',name:'reset.js',text:`const resetToken = Date.now(); console.log('resetToken', resetToken);`},
    {path:'proxy.js',name:'proxy.js',text:`fetch(req.query.url).then(x=>x.text())`},
    {path:'vm.js',name:'vm.js',text:`vm.runInNewContext(req.body.code)`},
    {path:'rng.js',name:'rng.js',text:`const token = Math.random();`},
    {path:'window.js',name:'window.js',text:`window.addEventListener('message', e=>el.innerHTML=e.data);`}
  ];
  const advancedResult = await E.scan(advanced,()=>{});
  const advancedIds = new Set(advancedResult.findings.map(f=>f.id));
  ['ACCESS-IDOR-001','AUTH-RESET-001','SSRF-002','DESER-003','CRYPTO-RNG-001','POSTMSG-004'].forEach(id=>assert(advancedIds.has(id), `Expected advanced rule ${id}`));
  assert(advancedResult.prompt.includes('Explain each security issue in plain language'), 'Repair prompt should include the plain-language teaching rule');

  const mirror = [
    {path:'README.md',name:'README.md',text:'hello'},
    {path:'CinderClip/README.md',name:'README.md',text:'hello'},
    {path:'server.py',name:'server.py',text:'print(1)'},
    {path:'CinderClip/server.py',name:'server.py',text:'print(1)'}
  ];
  const canonical = E.canonicalizeFiles(mirror);
  assert(canonical.length===2, `Mirrored project tree should collapse to 2 files, got ${canonical.length}`);
  console.log('ORION ENGINE TESTS PASSED');
  console.log(JSON.stringify({rules:E.RULES.length,badFindings:badResult.findings.length,badScore:badResult.score,safeFindings:safeResult.findings.length,canonicalFiles:canonical.length},null,2));
})().catch(err=>{ console.error(err.stack||err); process.exit(1); });
