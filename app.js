(function(){
  const $ = s => document.querySelector(s);
  const state = {files:[], result:null, filter:'all', selected:null, projectName:'Untitled project', findingsExpanded:false, search:''};
  const engineCount = $('#engineCount');
  engineCount.textContent = `${OrionEngine.RULES.length} checks loaded`;

  const sceneWrap=$('#sceneWrap'), scene=$('.scene'), core=$('#core');
  let dragging=false, lastX=0,lastY=0, rotX=-7, rotY=0, frame=0, tiltX=0, tiltY=0, sceneRect=null;
  const reducedMotion=window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  const updateSceneRect=()=>{ sceneRect=sceneWrap.getBoundingClientRect(); };
  const renderScene=()=>{
    frame=0;
    if(reducedMotion) return;
    scene.style.transform=`translate3d(0,0,0) rotateX(${rotX-tiltY}deg) rotateY(${rotY+tiltX}deg)`;
  };
  const scheduleScene=()=>{
    if(reducedMotion || frame) return;
    frame=requestAnimationFrame(renderScene);
  };
  updateSceneRect();
  window.addEventListener('resize',updateSceneRect,{passive:true});
  sceneWrap.addEventListener('pointerenter',()=>{updateSceneRect();sceneWrap.classList.add('is-hovered');});
  sceneWrap.addEventListener('pointerleave',()=>{
    if(dragging) return;
    tiltX=0; tiltY=0; sceneWrap.classList.remove('is-hovered'); scheduleScene();
  });
  sceneWrap.addEventListener('pointermove',e=>{
    const rect=sceneRect || sceneWrap.getBoundingClientRect();
    const nx=((e.clientX-rect.left)/Math.max(rect.width,1)-.5);
    const ny=((e.clientY-rect.top)/Math.max(rect.height,1)-.5);
    if(dragging){
      rotY += (e.clientX-lastX)*.24;
      rotX -= (e.clientY-lastY)*.18;
      lastX=e.clientX; lastY=e.clientY;
    }
    tiltX=nx*14; tiltY=ny*10;
    scheduleScene();
  },{passive:true});
  sceneWrap.addEventListener('pointerdown',e=>{
    dragging=true; lastX=e.clientX; lastY=e.clientY;
    sceneWrap.setPointerCapture?.(e.pointerId);
    sceneWrap.classList.add('is-dragging');
  });
  sceneWrap.addEventListener('pointerup',e=>{
    dragging=false; sceneWrap.classList.remove('is-dragging');
    try{sceneWrap.releasePointerCapture?.(e.pointerId);}catch(_){}
    scheduleScene();
  });
  sceneWrap.addEventListener('pointercancel',()=>{dragging=false;sceneWrap.classList.remove('is-dragging');scheduleScene();});

  const dropZone = $('#dropZone');
  const fileInput=$('#fileInput');
  const folderInput=$('#folderInput');
  const addFilesInput=$('#addFilesInput');
  const addFolderInput=$('#addFolderInput');
  const pickerMenu=$('#pickerMenu');

  function openPicker(input){
    input.value='';
    try{
      if(typeof input.showPicker==='function') input.showPicker();
      else input.click();
    }catch(e){ input.click(); }
    closePicker();
  }
  function closePicker(){
    pickerMenu?.classList.add('hidden');
    $('#chooseBtn')?.setAttribute('aria-expanded','false');
  }
  function togglePicker(anchor){
    if(!pickerMenu) return;
    const willOpen=pickerMenu.classList.contains('hidden');
    if(willOpen){
      const r=anchor.getBoundingClientRect();
      pickerMenu.style.left=`${Math.max(0,r.left)}px`;
      pickerMenu.style.top=`${Math.round(r.bottom+8)}px`;
      pickerMenu.classList.remove('hidden');
      anchor.setAttribute('aria-expanded','true');
    } else closePicker();
  }

  $('#chooseBtn').onclick=e=>{ e.preventDefault(); e.stopPropagation(); togglePicker(e.currentTarget); };
  $('#pickFilesBtn')?.addEventListener('click',()=>openPicker(fileInput));
  $('#pickFolderBtn')?.addEventListener('click',()=>openPicker(folderInput));
  $('#folderBtn').onclick=e=>{ e.preventDefault(); e.stopPropagation(); openPicker(folderInput); };
  $('#addMoreBtn')?.addEventListener('click',e=>{ e.preventDefault(); togglePicker(e.currentTarget); });
  $('#rescanBtn')?.addEventListener('click',async()=>{
    if(!state.files.length){toast('Add a project first');return;}
    await runScan();
  });
  $('#pickerMenu')?.addEventListener('click',e=>e.stopPropagation());
  document.addEventListener('click',e=>{
    if(pickerMenu && !pickerMenu.contains(e.target) && !e.target.closest('#chooseBtn') && !e.target.closest('#addMoreBtn')) closePicker();
  });
  document.addEventListener('keydown',e=>{
    if(e.key==='Escape') closePicker();
    if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='o'){
      e.preventDefault();
      togglePicker($('#chooseBtn'));
    }
    if((e.ctrlKey||e.metaKey) && e.shiftKey && e.key.toLowerCase()==='a' && state.files.length){
      e.preventDefault();
      togglePicker($('#addMoreBtn') || $('#chooseBtn'));
    }
  });

  dropZone.onclick=e=>{ if(e.target.closest('button,a,input')) return; openPicker(state.files.length ? addFilesInput : fileInput); };
  dropZone.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();openPicker(state.files.length ? addFilesInput : fileInput);}};
  ['dragenter','dragover'].forEach(ev=>dropZone.addEventListener(ev,e=>{e.preventDefault();dropZone.classList.add('dragging');}));
  ['dragleave','drop'].forEach(ev=>dropZone.addEventListener(ev,e=>{e.preventDefault();dropZone.classList.remove('dragging');}));
  dropZone.addEventListener('drop', async e => {
    try {
      const dropped = await collectDroppedFiles(e.dataTransfer);
      if(!dropped.length){ toast('Nothing readable was dropped. Try a ZIP or select the folder.'); return; }
      await handleFiles(dropped);
    } catch(err) {
      console.error(err);
      toast(`Could not read dropped files: ${err.message}`);
    }
  });
  fileInput.addEventListener('change', async e => { await handleFiles([...e.target.files]); e.target.value=''; });
  folderInput.addEventListener('change', async e => { await handleFiles([...e.target.files]); e.target.value=''; });
  addFilesInput.addEventListener('change', async e => { await handleFiles([...e.target.files]); e.target.value=''; });
  addFolderInput.addEventListener('change', async e => { await handleFiles([...e.target.files]); e.target.value=''; });

  $('#demoBtn').onclick=async()=>{ state.files=OrionEngine.makeTestProject(); state.projectName='Orion test project'; prepareScan(); await runScan(); };
  $('#resetBtn').onclick=()=>{state.files=[]; state.result=null; state.selected=null; state.filter='all'; state.findingsExpanded=false; state.search=''; $('#findingSearch').value=''; $('#clearFindingSearch').classList.add('hidden'); document.querySelectorAll('.filter').forEach((x,i)=>x.classList.toggle('active',i===0)); $('#scanPanel').classList.add('hidden'); $('#dropZone').scrollIntoView({behavior:'smooth'}); toast('Reset');};
  $('#copyPromptBtn').onclick=async()=>{ if(!state.result) return; if(await copyText(state.result.prompt)) toast('Repair prompt copied'); else toast('Copy failed — select the prompt manually'); };
  $('#downloadPromptBtn').onclick=()=>{ if(!state.result)return; downloadText('orion-repair-instructions.txt',state.result.prompt); };
  $('#downloadReportBtn').onclick=()=>{ if(!state.result)return; const report=makeReport(); downloadText('orion-security-report.json',JSON.stringify(report,null,2)); };
  $('#copySummaryBtn').onclick=async()=>{ if(!state.result)return; const s=summaryText(); if(await copyText(s)) toast('Summary copied'); else toast('Copy failed — select the summary manually'); };
  $('#filters').addEventListener('click',e=>{ const b=e.target.closest('.filter'); if(!b)return; state.filter=b.dataset.filter; state.findingsExpanded=false; document.querySelectorAll('.filter').forEach(x=>x.classList.toggle('active',x===b)); renderFindings(); });
  $('#seeAllBtn').addEventListener('click',()=>{ state.findingsExpanded=!state.findingsExpanded; renderFindings(); });
  $('#findingSearch')?.addEventListener('input',e=>{ state.search=e.target.value.trim().toLowerCase(); state.findingsExpanded=false; $('#clearFindingSearch').classList.toggle('hidden',!state.search); renderFindings(); });
  $('#clearFindingSearch')?.addEventListener('click',()=>{ state.search=''; $('#findingSearch').value=''; $('#clearFindingSearch').classList.add('hidden'); renderFindings(); $('#findingSearch').focus(); });
  $('#downloadSarifBtn')?.addEventListener('click',()=>{ if(!state.result)return; downloadText('orion-results.sarif',JSON.stringify(makeSarif(),null,2)); });

  async function handleFiles(rawFiles){
    if(!rawFiles.length){toast('No files selected');return;}
    // V1 stays local-first. The browser handles file/folder selection; Orion only analyzes readable source/config text.
    try {
      const expanded=[];
      for(const f of rawFiles){
        if(/\.zip$/i.test(f.name)) {
          expanded.push(...await readZip(f));
          continue;
        }
        const ext=(f.name.toLowerCase().match(/\.([a-z0-9]+)$/)||[])[1]||'';
        if(OrionEngine.SKIP_EXT.has(ext)) continue;
        if(f.size>MAX_DIRECT_FILE) { toast(`Skipped ${f.name}: file is larger than ${Math.round(MAX_DIRECT_FILE/1e6)} MB.`); continue; }
        const head=new Uint8Array(await f.slice(0,4096).arrayBuffer());
        if(head.includes(0)) continue;
        expanded.push({path:(f.webkitRelativePath||f.name).replace(/^\/*/,'').replace(/\\/g,'/'),name:f.name,size:f.size,text: await f.text()});
      }
      const before=state.files.length;
      const additions=OrionEngine.canonicalizeFiles(expanded.filter(f=>f.path && !f.path.endsWith('/')));
      state.files=OrionEngine.canonicalizeFiles([...state.files,...additions]);
      if(!state.files.length){ toast('No readable source files were found.'); return; }
      state.projectName = state.projectName!=='Untitled project' ? state.projectName : (state.files[0]?.path?.split('/')[0] || 'Website project');
      prepareScan();
      toast(before ? `Added ${Math.max(0,state.files.length-before)} file${state.files.length-before===1?'':'s'} · rescanning` : `Loaded ${state.files.length} files`);
      await runScan();
    } catch(err){ console.error(err); toast(`Could not read files: ${err.message}`); }
  }


  async function collectDroppedFiles(dataTransfer){
    const items=[...(dataTransfer?.items||[])];
    const entries=[];
    for(const item of items){
      if(item.kind!=='file') continue;
      const entry=item.webkitGetAsEntry?.();
      if(entry) entries.push(entry);
    }
    if(!entries.length) return [...(dataTransfer?.files||[])];

    const files=[];
    async function walk(entry, prefix=''){
      if(entry.isFile){
        await new Promise((resolve,reject)=>entry.file(file=>{
          try{
            Object.defineProperty(file,'webkitRelativePath',{value:`${prefix}${file.name}`,configurable:true});
          }catch(e){}
          files.push(file); resolve();
        },reject));
        return;
      }
      if(entry.isDirectory){
        const reader=entry.createReader();
        const children=[];
        while(true){
          const batch=await new Promise((resolve,reject)=>reader.readEntries(resolve,reject));
          if(!batch.length) break;
          children.push(...batch);
        }
        for(const child of children) await walk(child, `${prefix}${entry.name}/`);
      }
    }
    for(const entry of entries) await walk(entry,'');
    return files;
  }

  async function readZip(file){
    const buffer=await file.arrayBuffer(); const view=new DataView(buffer); const bytes=new Uint8Array(buffer);
    const findSig=(sig,start,end)=>{ for(let i=end-4;i>=start;i--){ if(view.getUint32(i,true)===sig)return i;} return -1; };
    const eocd=findSig(0x06054b50,Math.max(0,bytes.length-0xFFFF-22),bytes.length);
    if(eocd<0) throw new Error('ZIP end record not found');
    const cdSize=view.getUint32(eocd+12,true), cdOffset=view.getUint32(eocd+16,true); let p=cdOffset; const out=[];
    const decoder=new TextDecoder(); let totalUncompressed=0;
    const entryCount=view.getUint16(eocd+10,true);
    if(entryCount>MAX_ZIP_FILES) throw new Error(`ZIP contains too many entries (${entryCount}); limit is ${MAX_ZIP_FILES}.`);
    for(let i=0;i<entryCount;i++){
      if(view.getUint32(p,true)!==0x02014b50) break;
      const method=view.getUint16(p+10,true), compSize=view.getUint32(p+20,true), uncomp=view.getUint32(p+24,true), nameLen=view.getUint16(p+28,true), extraLen=view.getUint16(p+30,true), commentLen=view.getUint16(p+32,true), localOffset=view.getUint32(p+42,true);
      const name=decoder.decode(bytes.slice(p+46,p+46+nameLen)); p += 46+nameLen+extraLen+commentLen;
      if(name.endsWith('/')) continue;
      if(uncomp>MAX_ZIP_ENTRY) continue;
      totalUncompressed += uncomp;
      if(totalUncompressed>MAX_ZIP_TOTAL) throw new Error(`ZIP expands beyond the ${Math.round(MAX_ZIP_TOTAL/1e6)} MB analysis limit.`);
      const lp=localOffset; const nlen=view.getUint16(lp+26,true), xlen=view.getUint16(lp+28,true); const start=lp+30+nlen+xlen;
      const comp=bytes.slice(start,start+compSize);
      let data;
      if(method===0){data=comp;}
      else if(method===8){const ds=new DecompressionStream('deflate-raw'); data=new Uint8Array(await new Response(new Blob([comp]).stream().pipeThrough(ds)).arrayBuffer());}
      else continue;
      const ext=(name.toLowerCase().match(/\.([a-z0-9]+)$/)||[])[1]||'';
      if(OrionEngine.SKIP_EXT.has(ext)) continue;
      if(/\x00/.test(new TextDecoder().decode(data.slice(0,Math.min(data.length,4096))))) continue;
      out.push({path:name.replace(/\\/g,'/'),name:name.split('/').pop(),size:uncomp,text:new TextDecoder('utf-8',{fatal:false}).decode(data)});
    }
    return out;
  }
  const MAX_DIRECT_FILE=5_000_000; const MAX_ZIP_ENTRY=3_000_000; const MAX_ZIP_FILES=1200; const MAX_ZIP_TOTAL=30_000_000;

  function prepareScan(){
    $('#scanPanel').classList.remove('hidden');
    $('#projectName').textContent=state.projectName;
    $('#metricFiles').textContent=state.files.length;
    $('#metricFilesHint').textContent=`${state.files.filter(f=>OrionEngine.TEXT_EXT.has((f.path.match(/\.([a-z0-9]+)$/i)||[])[1]?.toLowerCase())).length} readable source`;
    $('#metricRules').textContent=OrionEngine.RULES.length;
    $('#scanState').textContent='QUEUED';
    $('#progressFill').style.width='0%'; $('#progressPct').textContent='0%'; $('#progressText').textContent='Ready to scan';
  }

  function setScanBusy(busy){
    ['addMoreBtn','rescanBtn','chooseBtn','folderBtn','demoBtn'].forEach(id=>{const el=document.getElementById(id);if(el)el.disabled=busy;});
    if(busy) closePicker();
  }

  function setProgress(pct, text){
    const safe=Math.max(0,Math.min(100,pct));
    $('#progressFill').style.width=`${safe}%`;
    $('#progressPct').textContent=`${safe}%`;
    $('#progressText').textContent=text;
  }

  async function runScan(){
    setScanBusy(true);
    $('#scanState').textContent='SCANNING';
    $('#promptCard').classList.add('hidden');
    $('#copyPromptBtn').disabled=true; $('#downloadPromptBtn').disabled=true;
    setProgress(1,'Preparing project analysis…');

    const result=await OrionEngine.scan(state.files, ({processed,total,file})=>{
      // File analysis is only the first stage. Reserve the final 6% for correlation,
      // prompt compilation, rendering and final verification so 100% means complete.
      const pct=total ? Math.min(94,Math.max(2,Math.floor(processed/total*94))) : 2;
      setProgress(pct,`Analyzing ${file?.path||'files'} · ${processed}/${total}`);
    });

    setProgress(95,'All files checked. Correlating related findings…');
    await new Promise(r=>setTimeout(r,0));
    setProgress(97,'Compiling plain-English repair instructions…');
    result.prompt=OrionEngine.compilePrompt(state.projectName,result.findings,result.files,result.intelligence);
    await new Promise(r=>setTimeout(r,0));
    setProgress(98,'Preparing the security report…');
    state.result=result;
    $('#scanState').textContent='FINALIZING';

    const confirmed = result.findings.filter(f=>!f.advisory);
    const reviews = result.findings.filter(f=>f.advisory);
    $('#metricFindings').textContent=confirmed.length;
    $('#metricFindingsHint').textContent=confirmed.length
      ? `${reviews.length ? `${reviews.length} review item${reviews.length===1?'':'s'} · ` : ''}${confirmed.filter(f=>f.severity==='critical'||f.severity==='high').length} important or urgent`
      : (reviews.length ? `${reviews.length} review item${reviews.length===1?'':'s'} · no confirmed problems` : 'no problems found');
    $('#metricScore').textContent=result.score;
    updatePlainSummary(result);
    renderPromptDocument(result.prompt);
    renderFindings();
    $('#promptCard').classList.remove('hidden');
    $('#copyPromptBtn').disabled=false; $('#downloadPromptBtn').disabled=false; $('#downloadReportBtn').disabled=false; $('#downloadSarifBtn').disabled=false; $('#copySummaryBtn').classList.remove('hidden');

    setProgress(99,'Finishing interface and verifying results…');
    await new Promise(r=>typeof requestAnimationFrame==='function' ? requestAnimationFrame(r) : setTimeout(r,16));
    $('#scanState').textContent='COMPLETE';
    setProgress(100,'Analysis complete');
    $('#scanPanel').scrollIntoView({behavior:'auto',block:'start'});
    toast(result.findings.length ? `Scan complete · ${result.findings.length} findings` : 'Scan complete · no matches');
    setScanBusy(false);
  }

  function renderPromptDocument(prompt){
    const host=$('#promptOutput');
    host.innerHTML='';
    const blocks=String(prompt||'').split(/\n\n+/);
    for(const block of blocks){
      const clean=block.trim();
      if(!clean) continue;
      const lines=clean.split('\n');
      const first=lines[0]||'';
      if(first==='ORION SECURITY REPAIR BRIEF'){
        const h=document.createElement('div'); h.className='prompt-doc-title'; h.textContent=first; host.appendChild(h);
        if(lines[1]){const meta=document.createElement('div'); meta.className='prompt-doc-meta'; meta.textContent=lines[1]; host.appendChild(meta);}
        continue;
      }
      const section=/^(GOAL|RULES FOR THE REPAIR AGENT|SECURITY ISSUES TO VERIFY AND FIX|REVIEW ITEMS — NOT CONFIRMED VULNERABILITIES|PROJECT FILE MAP|FINAL REPORT|VERIFICATION|CHECK)$/.test(first);
      if(section){
        const h=document.createElement('div'); h.className='prompt-doc-heading'; h.textContent=first; host.appendChild(h);
        if(lines.length>1){const body=document.createElement('div'); body.className='prompt-doc-body'; body.textContent=lines.slice(1).join('\n'); host.appendChild(body);}
        continue;
      }
      if(/^ISSUE \d+|^REVIEW ITEM \d+/.test(first)){
        const item=document.createElement('div'); item.className='prompt-doc-item';
        const heading=document.createElement('div'); heading.className='prompt-doc-item-head'; heading.textContent=first; item.appendChild(heading);
        const body=document.createElement('div'); body.className='prompt-doc-body'; body.textContent=lines.slice(1).join('\n'); item.appendChild(body);
        host.appendChild(item);
        continue;
      }
      const body=document.createElement('div'); body.className='prompt-doc-body'; body.textContent=clean; host.appendChild(body);
    }
  }

  function renderFindings(){
    const list=$('#findingList'); const overflow=$('#findingOverflow'); const seeAll=$('#seeAllBtn');
    if(!state.result){ overflow.classList.add('hidden'); return; }
    const query=state.search;
    const rows=state.result.findings.filter(f=>{
      const filterOk=state.filter==='all'||(state.filter==='advisory'?f.advisory:f.severity===state.filter);
      if(!filterOk) return false;
      if(!query) return true;
      const hay=[f.id,f.title,f.plainTitle,f.reason,f.plainWhy,f.fix,f.file,f.owasp,f.cwe].filter(Boolean).join(' ').toLowerCase();
      return hay.includes(query);
    });
    list.innerHTML='';
    if(!rows.length){ list.innerHTML='<div class="empty-state"><span class="empty-line"></span><span>No findings in this filter.</span></div>'; overflow.classList.add('hidden'); return; }
    const visible = state.findingsExpanded ? rows : rows.slice(0,10);
    visible.forEach((f,i)=>{
      const article=document.createElement('article');
      article.className=`finding-item severity-${f.severity}`;
      const number=document.createElement('div'); number.className='finding-number'; number.textContent=String(i+1).padStart(2,'0');
      const body=document.createElement('div'); body.className='finding-body';
      const head=document.createElement('div'); head.className='finding-head';
      const title=document.createElement('h4'); title.textContent=humanSentence(f);
      const severity=document.createElement('span'); severity.className=`finding-severity ${f.severity}`; severity.textContent=f.advisory?'REVIEW ITEM':severityLabel(f.severity);
      if (f.advisory) severity.classList.add('advisory');
      head.append(title,severity);

      const why=document.createElement('p'); why.className='finding-copy'; why.textContent=f.plainWhy||f.reason||'Orion found a pattern that deserves a closer security check.';
      const where=document.createElement('p'); where.className='finding-where';
      const location = `Found in <code>${escapeHtml(f.file)}</code>${Number.isFinite(Number(f.line))?` at line ${escapeHtml(f.line)}`:''}.`;
      const repeats = f.occurrences && f.occurrences.length>1 ? ` <span class="finding-repeat">Same pattern also seen ${f.occurrences.length-1} more time${f.occurrences.length-1===1?'':'s'}.</span>` : '';
      where.innerHTML=location+repeats;
      const fix=document.createElement('p'); fix.className='finding-fix'; fix.innerHTML=`<strong>What to do:</strong> ${escapeHtml(f.plainFix||f.fix||'Review this area and remove the unsafe behavior without changing unrelated functionality.')}`;

      const details=document.createElement('details'); details.className='finding-technical';
      const summary=document.createElement('summary'); summary.textContent='Technical details';
      const tech=document.createElement('div'); tech.className='technical-inline';
      tech.innerHTML=`<div><strong>Rule</strong> ${escapeHtml(f.id||'—')}</div><div><strong>Confidence</strong> ${escapeHtml(f.confidence||'—')}</div><div><strong>OWASP</strong> ${escapeHtml(f.owasp||'—')}</div><div><strong>CWE</strong> ${escapeHtml(f.cwe||'—')}</div><pre>${escapeHtml(f.evidence||'No evidence captured.')}</pre>`;
      details.append(summary,tech);
      body.append(head,why,where,fix,details);
      article.append(number,body);
      list.appendChild(article);
    });
    if(rows.length>10){
      overflow.classList.remove('hidden');
      seeAll.textContent = state.findingsExpanded ? 'Show fewer' : `See all ${rows.length} findings`;
    } else {
      overflow.classList.add('hidden');
    }
  }
  function humanSentence(f){
    const map={
      'Potential DOM XSS sink':'Your page puts data from the app directly into HTML without proving that it is safe.',
      'Session identifier appears in a URL parameter':'Your site puts a session ID into a web address instead of keeping it out of the URL.',
      'Original filename used directly in storage path':'Your server uses part of an uploaded filename when creating the stored file path.',
      'Potentially missing Content-Security-Policy':'Your deployment does not appear to tell the browser which scripts and resources are allowed to run.',
      'Potentially missing referrer policy':'Your deployment does not appear to limit how much page-address information is sent to other sites.',
      'Potentially missing frame-embedding protection':'Your site does not appear to prevent other sites from embedding its pages in a frame.',
      'Potentially missing MIME-sniffing protection':'Your deployment does not appear to tell browsers not to guess a file type.',
      'Cross-Origin-Opener-Policy not evident':'Your site does not appear to use an optional browser isolation setting.',
      'Cross-Origin-Embedder-Policy not evident':'Your site does not appear to use an optional cross-origin isolation setting.'
    };
    return map[f.title] || f.plainTitle || f.title || 'Orion found a security issue that needs review.';
  }
  function severityLabel(s){ return ({critical:'Needs urgent action',high:'Important',medium:'Should fix',low:'Worth checking'})[s] || 'Review'; }
  function detailIntro(f){
    if(f.severity==='critical') return 'This is the first thing to deal with because it could expose or seriously compromise the app.';
    if(f.severity==='high') return 'This is an important security problem and should be fixed before treating the site as ready.';
    if(f.severity==='medium') return 'This is not necessarily an active break-in, but it creates a weakness worth fixing.';
    return 'This is a smaller hardening or review item. It may not be a direct vulnerability on its own.';
  }
  function summaryText(){ const r=state.result; const confirmed=r.findings.filter(f=>!f.advisory), reviews=r.findings.filter(f=>f.advisory); const urgent=confirmed.filter(f=>f.severity==='critical').length, important=confirmed.filter(f=>f.severity==='high').length; return `ORION security check\nProject: ${state.projectName}\nSecurity score: ${r.score}/100\nConfirmed security issues: ${confirmed.length}\nReview items: ${reviews.length}\nNeeds urgent action: ${urgent}\nImportant: ${important}\n\n${r.findings.map(f=>`- ${f.plainTitle||f.title} (${f.advisory?'Review item':severityLabel(f.severity)})\n  ${f.plainWhy||f.reason}\n  File: ${f.file}, line ${f.line}`).join('\n')}`; }
  function makeReport(){ return {product:'ORION',version:1,project:state.projectName,generatedAt:new Date().toISOString(),scope:'local static analysis',limitations:'This is not a guarantee of security or legal compliance and does not replace dynamic testing or expert review.',rulesLoaded:OrionEngine.RULES.length,score:state.result.score,profile:state.result.profile,intelligence:state.result.intelligence || null,files:state.result.files,findings:state.result.findings}; }

  function updatePlainSummary(result){
    const urgent=result.findings.filter(f=>f.severity==='critical').length;
    const important=result.findings.filter(f=>f.severity==='high').length;
    const medium=result.findings.filter(f=>f.severity==='medium').length;
    const title=$('#plainSummaryTitle'); const copy=$('#plainSummaryCopy');
    if(!result.findings.length){
      title.textContent='Nothing obvious was found.';
      copy.textContent='That is a good sign, but it does not prove the website is completely secure. Dynamic testing and expert review can still find things static analysis cannot.';
      return;
    }
    const confirmed=result.findings.filter(f=>!f.advisory);
    const reviews=result.findings.filter(f=>f.advisory);
    const first=confirmed[0] || result.findings[0];
    const stackHint=result.intelligence?.summary?.stack && result.intelligence.summary.stack!=='Not confidently identified' ? ` Detected stack: ${result.intelligence.summary.stack}.` : '';
    if(!confirmed.length){
      title.textContent=`No confirmed security problems were found.`;
      copy.textContent=`Orion did find ${reviews.length} review item${reviews.length===1?'':'s'} that should be checked in your real deployment or application flow. These are not counted as confirmed vulnerabilities.`;
      return;
    }
    title.textContent=`Orion found ${confirmed.length} ${confirmed.length===1?'security issue':'security issues'} worth fixing${reviews.length?` and ${reviews.length} review item${reviews.length===1?'':'s'}`:''}.`;
    const lead=[];
    if(urgent) lead.push(`${urgent} ${urgent===1?'needs':'need'} urgent action`);
    if(important) lead.push(`${important} ${important===1?'is':'are'} important`);
    if(medium) lead.push(`${medium} ${medium===1?'should':'should'} be fixed`);
    const intelligenceHint=result.intelligence ? ` Orion also mapped ${result.intelligence.trustSources?.length||0} trust-source signals and ${result.intelligence.safeBoundaries?.length||0} safety boundaries before ranking these results.` : '';
    copy.textContent=`Start with “${first.plainTitle||first.title}”. ${lead.join(', ')}${lead.length?', and':''} every issue is explained below in normal language.${stackHint}${intelligenceHint}`;
  }

  function makeSarif(){
    const findings=state.result?.findings||[];
    return {
      version:'2.1.0',
      $schema:'https://json.schemastore.org/sarif-2.1.0.json',
      runs:[{
        tool:{
          driver:{
            name:'Orion',
            version:'1',
            informationUri:'https://github.com/devansh-ggW/Orion',
            rules:[...new Map(findings.map(f=>[f.id,{id:f.id,name:f.title,shortDescription:{text:f.plainTitle||f.title},help:{text:f.plainFix||f.fix||'Review the flagged code path.'}}])).values()]
          }
        },
        results:findings.map(f=>({
          ruleId:f.id,
          level:f.severity==='critical'||f.severity==='high'?'error':f.severity==='medium'?'warning':'note',
          message:{text:f.plainWhy||f.reason||f.title},
          locations:f.file?[{physicalLocation:{artifactLocation:{uri:f.file},region:{startLine:Number(f.line)||1}}}]:[],
          properties:{advisory:!!f.advisory,confidence:f.confidence||'unknown',evidenceTier:f.evidenceTier||'pattern',owasp:f.owasp||null,cwe:f.cwe||null}
        }))
      }]
    };
  }

  async function copyText(text){
    try { if(navigator.clipboard && window.isSecureContext){ await navigator.clipboard.writeText(text); return true; } } catch(e){}
    const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select();
    let ok=false; try{ok=document.execCommand('copy');}catch(e){} ta.remove(); return ok;
  }
  function downloadText(name,text){ const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([text],{type:'text/plain'})); a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),1500); }
  function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
  let toastTimer; function toast(msg){const el=$('#toast');el.textContent=msg;el.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.classList.remove('show'),2200);}
})();
