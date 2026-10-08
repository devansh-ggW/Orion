/* ORION Security Intent Engine — V1
 * Deterministic-first, local-only static analysis.
 * This intentionally avoids claiming complete vulnerability coverage.
 */
(function () {
  const TEXT_EXT = new Set(['html','htm','js','mjs','cjs','ts','tsx','jsx','css','json','yaml','yml','xml','md','txt','env','conf','config','php','py','go','rs','java','kt','kts','rb','cs','csharp','sql','toml','ini','vue','svelte','map','sh','bash','ps1','tf','tfvars','hcl','dockerfile']);
  const SKIP_EXT = new Set(['png','jpg','jpeg','gif','webp','avif','ico','svgz','mp4','webm','mov','mp3','wav','woff','woff2','ttf','otf','eot','pdf','zip','gz','7z','rar','bin','exe','dll']);
  const MAX_TEXT_BYTES = 1_500_000;
  const KNOWLEDGE = window.OrionKnowledge || {};
  // Merge extra teaching data shipped with the expanded pattern pack.
  if (window.OrionPatternPack?.KNOWLEDGE) {
    const pk=window.OrionPatternPack.KNOWLEDGE;
    const teaching=KNOWLEDGE.teaching=KNOWLEDGE.teaching||{};
    const p=teaching.patterns=teaching.patterns||{};
    const mergeList=(key,values)=>{ if(!Array.isArray(values)) return; p[key]=Array.from(new Set([...(p[key]||[]),...values])); };
    mergeList('browserSources',pk.browserSources);
    mergeList('serverSources',pk.serverSources);
    mergeList('dangerousSinks',pk.dangerousSinks);
    mergeList('safeBoundaries',pk.safeBoundaries);
    mergeList('antiPatterns',pk.antiPatterns);
    teaching.frameworks=Object.assign({},teaching.frameworks||{},pk.frameworks||{});
    teaching.verificationModules=Array.from(new Set([...(teaching.verificationModules||[]),...(pk.verificationModules||[])]));
  }

  const RULES = [
    {id:'JS-EVAL-001',category:'Injection',severity:'high',title:'Dynamic code execution',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/\beval\s*\(|\bnew\s+Function\s*\(/g,reason:'Dynamic code execution can turn attacker-controlled strings into executable JavaScript.',fix:'Replace dynamic execution with explicit data handling or a constrained parser. Preserve behavior without evaluating arbitrary strings.',guard:/trustedInternalExpression|ALLOW_EVAL|eslint-disable.*no-eval/i},
    {id:'JS-TIMEOUT-001',category:'Injection',severity:'medium',title:'String-based timer execution',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/\b(?:setTimeout|setInterval)\s*\(\s*[\'\"]/g,reason:'A string passed to a timer API is evaluated as code in many browser environments.',fix:'Pass a function callback instead of executable source text.'},
    {id:'DOM-XSS-001',category:'Cross-Site Scripting',severity:'medium',title:'Potential DOM XSS sink',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte','html','htm'],pattern:/\.(?:innerHTML|outerHTML|insertAdjacentHTML)\s*(?:=|\()/g,reason:'HTML-writing sinks are dangerous when their input can be influenced by users or remote data.',fix:'Prefer textContent/DOM APIs for plain text. When HTML is truly required, sanitize with a well-maintained allowlist sanitizer and validate the source.',guard:/textContent|DOMPurify|sanitizeHtml|sanitize\s*\(/i},
    {id:'DOM-XSS-002',category:'Cross-Site Scripting',severity:'high',title:'Potential DOM XSS source-to-sink flow',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],flow:{maxDistance:750,sources:[/location\.(?:search|hash|href)/i,/document\.URL/i,/URLSearchParams/i,/localStorage\./i,/sessionStorage\./i,/\.value\b/i],sinks:[/\.innerHTML\b/i,/\.outerHTML\b/i,/insertAdjacentHTML\s*\(/i]},reason:'A value from a browser-controlled or user-controlled source appears near an HTML sink.',fix:'Trace the value from source to sink. Encode or sanitize it before HTML rendering, or change the sink to a text/DOM API.'},
    {id:'DOM-XSS-003',category:'Cross-Site Scripting',severity:'medium',title:'Direct document.write usage',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte','html','htm'],pattern:/\bdocument\.write(?:ln)?\s*\(/g,reason:'document.write can inject markup into a live document and is difficult to reason about safely.',fix:'Replace document.write with explicit DOM construction or templating.'},
    {id:'WEB-REDIRECT-001',category:'Unvalidated Redirects',severity:'medium',title:'Redirect target appears externally controllable',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte','php','py','go','java','rb'],pattern:/\b(?:window\.location|location\.href|location\.assign|location\.replace|res\.redirect|redirect)\s*\([^\n;]{0,180}(?:req\.|request\.|query|params|searchParams|next|returnUrl|redirectUrl)/gi,reason:'Redirect destinations influenced by request parameters can create phishing-friendly open redirects.',fix:'Allow only known internal paths or an explicit allowlist of trusted origins.'},
    {id:'WEB-REDIRECT-002',category:'Unvalidated Redirects',severity:'low',advisory:true,title:'External redirect API detected',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte','php','py','go','java','rb'],pattern:/\b(?:window\.location\s*=|location\.assign\s*\(|location\.replace\s*\(|res\.redirect\s*\()/g,reason:'Redirect behavior deserves a manual check when the destination is built from dynamic data.',fix:'Verify redirect destinations are constrained to trusted paths/origins.'},
    {id:'SECRETS-001',category:'Secrets',severity:'critical',title:'Possible secret or private key embedded in source',ext:['js','mjs','cjs','ts','tsx','jsx','json','yaml','yml','env','conf','config','php','py','go','rs','java','rb'],pattern:/(?:-----BEGIN (?:RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----|(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*["'][^"'\n]{12,}["'])/gi,reason:'Long-lived credentials in source can be exposed through source control, builds, browser bundles, or logs.',fix:'Move real secrets to a server-side secret store or environment variable. Do not expose credentials in browser-delivered code.',guard:/example|changeme|your[_-]?key|replace[_-]?me|dummy|test[_-]?secret/i},
    {id:'SECRETS-002',category:'Secrets',severity:'high',title:'Cloud credential pattern detected',ext:['js','mjs','cjs','ts','tsx','jsx','json','yaml','yml','env','conf','config','php','py','go','rs','java','rb'],pattern:/(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{12,})/g,reason:'Recognizable provider credential formats should not live in client-delivered or committed code.',fix:'Revoke exposed credentials when real, rotate them, and move secret usage to a server-side boundary.',guard:/example|placeholder|sample/i},
    {id:'AUTH-001',category:'Authentication',severity:'high',title:'Authentication state stored in browser storage',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/\b(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*[\'\"](?:token|accessToken|refreshToken|jwt|auth|session)/gi,reason:'Browser storage is readable by JavaScript in the page context, so a script injection can expose bearer credentials.',fix:'Prefer secure, appropriately scoped cookies for session material and keep long-lived secrets off the client.'},
    {id:'AUTH-002',category:'Authentication',severity:'medium',title:'JWT token appears to be decoded without verification',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/\b(?:jwtDecode|decodeJwt|atob)\s*\([^\n;]{0,160}(?:token|jwt|authorization)/gi,reason:'Decoding a token is not the same as verifying its signature and claims.',fix:'Verify signature, issuer, audience, expiry, and relevant claims on a trusted server boundary.'},
    {id:'AUTH-003',category:'Authentication',severity:'medium',title:'Password-like value logged',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb','python'],pattern:/\b(?:console\.log|print|logger\.(?:info|debug|warn|error))\s*\([^\n]{0,160}\b(?:password|passwd|pwd|secret|token)\b/gi,reason:'Authentication or secret material should not be written to logs.',fix:'Remove sensitive values from logs and replace them with non-sensitive identifiers.'},
    {id:'COOKIE-001',category:'Cookies',severity:'high',confidenceBase:'medium',title:'Cookie may be missing important security flags',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],check:(text)=>{const hits=[]; const rx=/\b(?:res\.cookie|res\.setHeader\s*\(\s*[\"']Set-Cookie[\"']|setCookie|Set-Cookie)\b/gi; for(const m of allMatches(rx,text,12)){const context=text.slice(Math.max(0,m.index-100),Math.min(text.length,m.index+460)).replace(/\n/g,' '); const sessionish=/session|token|auth|login/i.test(context); const secure=/\bsecure\b/i.test(context), httpOnly=/\bhttponly\b/i.test(context), sameSite=/\bsamesite\s*[:=]/i.test(context); if(sessionish && (!secure || !httpOnly || !sameSite)) hits.push({index:m.index});} return hits;},reason:'A cookie used for login or session state may not have all of the protections your authentication flow needs.',fix:'For session cookies, set Secure and HttpOnly when appropriate and choose SameSite deliberately for the real login flow. Not every cookie needs every flag.'},
    {id:'COOKIE-002',category:'Cookies',severity:'medium',title:'SameSite=None cookie without an obvious Secure flag',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/\bSameSite\s*=\s*None\b(?![^\n]{0,80}\bSecure\b)/gi,reason:'Cross-site cookies generally require Secure and should only be used when cross-site behavior is intentional.',fix:'Use SameSite=Lax/Strict where possible. When None is required, ensure Secure is also set.'},
    {id:'CORS-001',category:'CORS',severity:'high',title:'Wildcard CORS with credentials',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/(?:Access-Control-Allow-Origin|origin\s*:)\s*["'`]\*["'`][\s\S]{0,260}(?:credentials|Allow-Credentials)\s*[:=]\s*true/gi,reason:'Wildcard origins combined with credentialed cross-origin access can expose authenticated responses.',fix:'Use an explicit allowlist of trusted origins and enable credentials only where required.'},
    {id:'CORS-002',category:'CORS',severity:'medium',title:'Origin reflection appears enabled',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/(?:Access-Control-Allow-Origin|origin\s*:)\s*(?:req(?:uest)?\.headers\.(?:origin)|request\.headers\.get\([\'\"]origin)/gi,reason:'Reflecting arbitrary Origin headers can effectively allow any site to access responses.',fix:'Validate the origin against a trusted allowlist before reflecting it.'},
    {id:'INJECT-SQL-001',category:'Injection',severity:'medium',confidenceBase:'medium',title:'SQL query built with string interpolation',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb','py'],pattern:/(?:SELECT|INSERT|UPDATE|DELETE)[^\n;]{0,260}(?:\$\{|\+\s*[a-zA-Z_$]|\.concat\s*\()/gi,reason:'Concatenating untrusted values into SQL creates injection risk.',fix:'Use parameterized queries or a safe query builder with bound values.'},
    {id:'INJECT-SQL-002',category:'Injection',severity:'high',title:'Raw SQL execution receives request-like input',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/\b(?:query|execute|raw|exec)\s*\([^\n]{0,240}(?:req\.|request\.|params|query|body|formData|input)/gi,reason:'Request-derived values reaching raw SQL execution should be treated as injection-sensitive.',fix:'Bind user data as parameters and avoid constructing executable SQL strings.'},
    {id:'INJECT-CMD-001',category:'Command Injection',severity:'critical',title:'OS command execution with dynamic input',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/\b(?:child_process\.(?:exec|execFile)|exec\s*\(|spawn\s*\()[^\n]{0,240}(?:req\.|request\.|query|params|body|input|user)/gi,reason:'Dynamic OS command execution can become arbitrary command execution when user input reaches the command boundary.',fix:'Avoid shell execution. Prefer fixed executable arguments with allowlists and no shell interpretation.'},
    {id:'PATH-001',category:'Path Traversal',severity:'high',title:'Filesystem path built from request input',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/\b(?:readFile|writeFile|unlink|rm|open|createReadStream|createWriteStream)\s*\([^\n]{0,200}(?:req\.|request\.|query|params|body|filename|fileName|path)/gi,reason:'Request-controlled filesystem paths can allow traversal outside the intended directory.',fix:'Resolve against a fixed base directory, normalize the path, and allow only expected filenames or IDs.'},
    {id:'UPLOAD-001',category:'File Uploads',severity:'high',occurrence:'per-file',title:'File upload reaches a storage/processing sink without an obvious type boundary' ,confidenceBase:'medium',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],flow:{maxDistance:1200,sources:[/(?:request\.files|req\.files|req\.file|request\.files\[|req\.files\[|multer\s*\(|formidable\s*\(|busboy\s*\(|UploadFile\s*\(|FormFile\s*\(|\$_FILES)/i,/multipart\/form-data/i],sinks:[/\b(?:write_bytes|writeFile|writeFileSync|createWriteStream|fs\.rename|fs\.copyFile|save\s*\(|move_uploaded_file|\.save\s*\(|upload\s*\()/i]},reason:'An uploaded object appears to reach file storage or processing without an obvious allowlist boundary.',fix:'Validate size, extension and actual content type; generate a safe server-side name and keep uploads outside executable/static paths. Reject unexpected types before storage or processing.',guard:/mimetype|content.?type|allowed(?:_)?types|allowlist|extension|extensions|fileFilter|limits\s*[:=]|\bsuffix\b|\b(?:supported|unsupported)\s+(?:file|video|image|audio)\s+format/i},
    {id:'PATH-002',category:'File Uploads',severity:'medium',title:'Original filename may influence a storage path',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:originalname|originalName|filename)\b[\s\S]{0,260}(?:path\.join|join\s*\(|save\s*\(|write_bytes|writeFile|writeFileSync|createWriteStream)/gi,reason:'User-supplied filenames can become traversal or collision risks when they reach a filesystem path.',fix:'Prefer a server-generated opaque filename. Preserve the original name only as validated metadata. Review the filename sanitization function rather than assuming it is safe.',guard:/(?:safe_?filename|secure_?filename|sanitize_?filename|path\.basename|basename\s*\(|slugify\s*\()/i},
    {id:'CSRF-001',category:'CSRF',severity:'medium',title:'Cookie-authenticated state changes lack an obvious CSRF boundary',projectWide:true,ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],flow:{sources:[/\b(?:app|router|server|self)\.(?:post|put|patch|delete)\s*\(/i,/\b(?:do_POST|do_PUT|do_PATCH|do_DELETE)\b/i],sinks:[/\b(?:Cookie|Set-Cookie|req\.cookies|request\.cookies|session|session_id|cookie-parser|express-session|SameSite)\b/i]},reason:'Cookie-authenticated state changes need a deliberate CSRF defense when cross-site requests could be accepted.',fix:'Use SameSite cookies appropriately and/or a robust CSRF token plus Origin/Referer validation for state-changing requests. Do not add CSRF protection to stateless bearer-auth endpoints unless their auth model requires it.'},
    {id:'HEADERS-001',category:'Headers',severity:'medium',title:'Potentially missing Content-Security-Policy',ext:['html','htm','php','js','mjs','cjs','ts','tsx','jsx'],projectWide:true,absence:{anchor:/<head\b/i,absent:/Content-Security-Policy/i},reason:'A strong CSP can reduce the impact of certain script injection classes.',fix:'Add a deliberate CSP tailored to the site\'s actual script, style, image, font, connect, and frame requirements.'},
    {id:'HEADERS-002',category:'Headers',severity:'low',title:'Potentially missing referrer policy',ext:['html','htm','php'],projectWide:true,absence:{anchor:/<head\b/i,absent:/referrer-policy|<meta[^>]+name=[\"\']referrer/i},reason:'A restrictive Referrer-Policy can reduce unintended URL leakage to third parties.',fix:'Set a deliberate Referrer-Policy, commonly strict-origin-when-cross-origin or stricter depending on requirements.'},
    {id:'HEADERS-003',category:'Headers',severity:'low',title:'Potentially missing frame-embedding protection',ext:['html','htm','php'],projectWide:true,absence:{anchor:/<head\b/i,absent:/(?:frame-ancestors|X-Frame-Options)/i},reason:'Without frame-embedding controls, sensitive pages may be framed by other origins.',fix:'Use CSP frame-ancestors and/or X-Frame-Options according to the app\'s embedding requirements.'},
    {id:'HTTP-001',category:'Transport',severity:'medium',title:'Hard-coded insecure HTTP URL',ext:['html','htm','js','mjs','cjs','ts','tsx','jsx','css','json','yaml','yml','php','py','go','java','rb'],pattern:/\bhttp:\/\/[^\s"'<>]+/gi,reason:'Unencrypted HTTP resources can enable interception or mixed-content issues.',fix:'Use HTTPS for external resources and APIs unless the target is intentionally local/development-only.',guard:/localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com/i},
    {id:'HTTP-002',category:'Transport',severity:'low',title:'WebSocket URL uses ws://',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte','html','htm'],pattern:/\bws:\/\/[^\s"'<>]+/gi,reason:'Unencrypted WebSocket traffic can be intercepted on untrusted networks.',fix:'Use wss:// for production traffic.'},
    {id:'DEBUG-001',category:'Information Exposure',severity:'low',title:'Verbose debug statement in shipped code',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte','php','py','go','java','rb'],pattern:/\b(?:console\.debug|debugger\b|print\s*\(\s*[\'\"]DEBUG|process\.env\.DEBUG\s*=\s*true)/gi,reason:'Debug output and breakpoints can expose implementation details or remain enabled unintentionally.',fix:'Remove development-only debugging paths or gate them behind an explicit non-production environment.'},
    {id:'ERROR-001',category:'Information Exposure',severity:'medium',title:'Potential stack trace exposed to response',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/(?:res\.send|res\.json|response\.(?:send|json)|return\s+.{0,40})(?:err\.stack|error\.stack|exception\.stack)/gi,reason:'Stack traces reveal internal paths and implementation details.',fix:'Return a generic error to clients and log detailed diagnostics only on trusted server-side logging.'},
    {id:'DEPEND-001',category:'Supply Chain',severity:'low',advisory:true,title:'Dependency manifest present — review lockfile and versions',fileName:/(?:package\.json|pyproject\.toml|Cargo\.toml|go\.mod|composer\.json|requirements\.txt)$/i,ext:['json','yaml','yml','toml','txt'],pattern:/(?:"dependencies"|"devDependencies"|dependencies:|devDependencies:)/g,reason:'Third-party packages expand the attack surface and should be pinned and audited.',fix:'Keep lockfiles under version control, remove unused dependencies, and audit package versions through the package manager.'},
    {id:'DEPEND-002',category:'Supply Chain',severity:'low',advisory:true,title:'Install lifecycle script detected',fileName:/package\.json$/i,ext:['json'],pattern:/"(?:preinstall|install|postinstall)"\s*:/gi,reason:'Package lifecycle scripts execute during installation and deserve explicit trust review.',fix:'Review every lifecycle script and remove unnecessary execution hooks.'},
    {id:'HTML-001',category:'Cross-Site Scripting',severity:'medium',title:'Inline event handler detected',ext:['html','htm','svg'],pattern:/\bon(?:click|load|error|mouseover|mouseenter|mouseleave|focus|blur)\s*=\s*["']/gi,reason:'Inline handlers complicate CSP and can become injection primitives when markup is dynamically assembled.',fix:'Move event handling to script code and use a CSP that does not require unsafe-inline.'},
    {id:'HTML-002',category:'Cross-Site Scripting',severity:'medium',title:'javascript: URL detected',ext:['html','htm','js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/\bhref\s*=\s*["']\s*javascript:/gi,reason:'javascript: URLs turn link navigation into script execution.',fix:'Use real URLs or event handlers instead.'},
    {id:'HTML-003',category:'Target Security',severity:'low',advisory:true,title:'External link does not explicitly include rel=noopener',ext:['html','htm','php'],pattern:/<a\b(?=[^>]*\btarget\s*=\s*["']_blank["'])(?![^>]*\brel\s*=\s*["'][^"']*\bnoopener\b[^"']*["'])[^>]*>/gi,reason:'New windows should not receive a live opener reference when it is unnecessary.',fix:'Add rel="noopener" to target=_blank links or remove the target when not needed.'},
    {id:'CRYPTO-001',category:'Cryptography',severity:'high',title:'Weak hash algorithm usage',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb','py'],pattern:/\b(?:md5|sha1)\b/gi,reason:'MD5 and SHA-1 are unsuitable for many security-sensitive integrity or password-hashing uses.',fix:'Use modern primitives appropriate to the task. For passwords, use a dedicated password hashing function such as Argon2id, scrypt, or bcrypt.'},
    {id:'CRYPTO-002',category:'Cryptography',severity:'medium',title:'Hard-coded cryptographic key-like value',ext:['js','mjs','cjs','ts','tsx','jsx','json','yaml','yml','php','py','go','java','rb'],pattern:/(?:encryptionKey|signingKey|secretKey|privateKey)\s*[:=]\s*["'][^"'\n]{16,}["']/gi,reason:'Long-lived cryptographic keys should not be embedded in source or browser bundles.',fix:'Move secret key material to a server-side secret manager and rotate exposed keys.'},
    {id:'AUTH-004',category:'Authentication',severity:'high',title:'Password comparison without an obvious password-hash API',ext:['php','py','go','java','rb','js','mjs','cjs','ts'],pattern:/(?:password|passwd|pwd)\s*={2,3}\s*(?:req\.|request\.|body|input|form)|(?:req\.|request\.|body|input|form)[^\n]{0,80}(?:password|passwd|pwd)\b[^\n]{0,80}\s*={2,3}/gi,reason:'Direct string comparison of passwords is usually a design smell and may indicate plaintext password handling.',fix:'Use a dedicated password hashing and verification API with a modern adaptive password hash.'},
    {id:'ACCESS-001',category:'Access Control',severity:'high',title:'Object lookup uses request-controlled identifier without an obvious ownership check',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb','sql'],pattern:/(?:findById|findOne|findUnique|where\s*:\s*\{[^\n]{0,80}(?:id|userId)|SELECT[^\n]{0,160}WHERE[^\n]{0,100}(?:id|user_id))[^\n]{0,180}(?:req\.|request\.|params|query|body|input)/gi,reason:'Request-controlled record identifiers should be checked against the authenticated subject or allowed role.',fix:'Enforce authorization at the data-access boundary. Do not rely on the UI hiding records.'},
    {id:'ACCESS-002',category:'Access Control',severity:'medium',title:'Admin-like route lacks an obvious authorization guard nearby',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:\/admin|\/administrator|\/manage|\/staff)["'`][^\n]{0,220}(?:router\.|app\.|route\(|get\(|post\(|put\(|patch\(|delete\()/gi,reason:'Privileged routes need explicit server-side authorization checks.',fix:'Verify role/permission middleware protects the route and the underlying action, not only the UI.'},
    {id:'SSRF-001',category:'SSRF',severity:'high',title:'Server-side request target appears user-controlled',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:fetch|axios\.(?:get|post|request)|http(?:s)?\.request|got\s*\(|requests\.(?:get|post)|urllib\.request)[^\n]{0,220}(?:req\.|request\.|query|params|body|url)/gi,reason:'A server-side HTTP client pointed at attacker-controlled URLs can enable SSRF into internal services.',fix:'Allowlist permitted hosts/protocols, block private/link-local destinations, and avoid unrestricted URL fetching.'},
    {id:'TEMPLATE-001',category:'Injection',severity:'high',title:'Template rendering receives raw request-controlled content',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:render|template|compile|res\.render)[^\n]{0,220}(?:req\.|request\.|query|params|body|input)/gi,reason:'Dynamic template content requires strict escaping or controlled variables to avoid server-side template injection.',fix:'Pass untrusted values as escaped data fields; never treat them as template source.'},
    {id:'LOG-001',category:'Information Exposure',severity:'medium',title:'Authorization header or token logged',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/\b(?:console\.log|logger\.(?:info|debug|warn|error)|print\s*\()[^\n]{0,180}(?:authorization|bearer|access_token|refresh_token|api[_-]?key|cookie)/gi,reason:'Auth headers and tokens in logs create a second path to credential exposure.',fix:'Redact sensitive headers and values before logging.'},
    {id:'CONFIG-001',category:'Configuration',severity:'medium',title:'Development environment flag appears hard-coded',ext:['js','mjs','cjs','ts','tsx','jsx','json','yaml','yml','php','py','go','java','rb'],pattern:/(?:NODE_ENV|APP_ENV|ENVIRONMENT|DEBUG)\s*[:=]\s*["'](?:development|dev|debug|true)["']/gi,reason:'Production deployments can accidentally inherit development-only behavior.',fix:'Derive environment from trusted deployment configuration and disable development diagnostics in production.'},
    {id:'CONFIG-002',category:'Configuration',severity:'medium',title:'Dangerous permissive setting detected',ext:['js','mjs','cjs','ts','tsx','jsx','json','yaml','yml','php','py','go','java','rb'],pattern:/(?:allowAll|allow_any|permitAll|publicAccess|anonymousAccess|skipAuth)\s*[:=]\s*(?:true|1|["']true["'])/gi,reason:'Permissive configuration can bypass intended protection when enabled in production.',fix:'Default to deny. Restrict the setting to explicitly public routes or development environments.'},
    {id:'DEPEND-003',category:'Supply Chain',severity:'low',advisory:true,title:'Unpinned remote script dependency',ext:['html','htm','php','js','mjs','cjs','ts','tsx','jsx'],pattern:/<script\b[^>]+src\s*=\s*["'][^"']+@(?:latest|main|master|next)(?:["'?])/gi,reason:'Floating third-party script versions can change without a review and increase supply-chain risk.',fix:'Pin third-party assets to a known version and use Subresource Integrity when appropriate.'},
    {id:'DEPEND-004',category:'Supply Chain',severity:'low',advisory:true,occurrence:'per-file',title:'External script lacks Subresource Integrity',ext:['html','htm','php'],pattern:/<script\b(?=[^>]*\bsrc\s*=\s*["']https?:\/\/[^"']+["'])(?![^>]*\bintegrity\s*=)[^>]*>/gi,reason:'Third-party scripts can change outside your deployment process.',fix:'Pin the dependency and consider integrity metadata plus a strong CSP.'},
    {id:'PRIV-001',category:'Privacy',severity:'low',title:'Third-party analytics or tracking SDK detected',ext:['html','htm','js','mjs','cjs','ts','tsx','jsx','php'],pattern:/(?:googletagmanager|google-analytics|gtag\s*\(|facebook\.net\/en_US\/fbevents|clarity\.ms|hotjar|mixpanel|segment\.(?:io|com)|amplitude)/gi,reason:'Tracking technologies can create privacy and consent obligations depending on jurisdiction and purpose.',fix:'Document what data the tracker collects, provide required notice/consent controls, and load non-essential trackers only after the appropriate user choice.'},
    {id:'PRIV-002',category:'Privacy',severity:'medium',title:'Form collects personal-data fields',ext:['html','htm','js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/\b(?:name|email|phone|telephone|address|dateOfBirth|dob|location|ip)\b[^\n]{0,130}(?:<input|input\s*\(|formData|new\s+FormData)/gi,reason:'Collecting personal data creates notice, minimization, retention, and security obligations.',fix:'Document purpose and retention, collect only what is needed, and route sensitive data through appropriate controls.'},
    {id:'PRIV-003',category:'Privacy',severity:'low',title:'Privacy or cookie policy reference not detected',ext:['html','htm','php'],projectWide:true,absence:{anchor:/<(?:body|main|footer)\b/i,absent:/privacy|cookie policy|terms/i},reason:'A public-facing privacy/cookie notice may be required depending on the data processing and jurisdiction.',fix:'Review applicable requirements and add clear policy links and notices where appropriate. This is a readiness signal, not legal advice.'},
    {id:'HEADER-CTO-001',category:'Headers',severity:'low',title:'Potentially missing MIME-sniffing protection',ext:['html','htm','php'],projectWide:true,absence:{anchor:/<head\b/i,absent:/nosniff/i},reason:'X-Content-Type-Options: nosniff can prevent certain MIME confusion attacks.',fix:'Set X-Content-Type-Options: nosniff at the server/edge layer.'},
    {id:'AUTH-005',category:'Authentication',severity:'medium',title:'Password reset flow appears to accept a user identifier in the URL',ext:['html','htm','js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/(?:reset|forgot)[^\n]{0,180}(?:email=|user=|username=|id=)/gi,reason:'Account recovery links must use high-entropy, single-use, expiring reset tokens rather than guessable identifiers.',fix:'Use opaque, expiring, single-use reset tokens and avoid exposing account identifiers unnecessarily.'},
    {id:'POSTMSG-001',category:'Cross-Window Messaging',severity:'high',title:'postMessage listener lacks an obvious origin check',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/addEventListener\s*\(\s*[\"\']message[\"\'][\s\S]{0,500}(?!event\.origin|e\.origin|origin\s*===|allowedOrigins)/i,reason:'Cross-window messages can be sent by other origins unless the receiver validates the sender origin.',fix:'Validate event.origin against an explicit trusted-origin allowlist before acting on message data.'},
    {id:'POSTMSG-002',category:'Cross-Window Messaging',severity:'medium',title:'postMessage sent to wildcard origin',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/\.postMessage\s*\([^\n]{0,280},\s*[\"\']\*[\"\']/gi,reason:'A wildcard targetOrigin sends data to any receiving origin and can leak sensitive message payloads.',fix:'Use the exact trusted target origin whenever the recipient is known.'},
    {id:'RANDOM-001',category:'Cryptography',severity:'medium',title:'Math.random used near token-like data',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte','php','py','go','java','rb'],pattern:/Math\.random\s*\(\s*\)[\s\S]{0,180}(?:token|secret|key|nonce|session|password)/gi,reason:'Math.random is not designed for security-sensitive unpredictability.',fix:'Use a cryptographically secure random source for security tokens and secrets.'},
    {id:'PROTO-001',category:'Injection',severity:'high',title:'Object merge receives request body without an obvious key filter',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/(?:Object\.assign|lodash\.(?:merge|defaultsDeep)|merge\s*\()[^\n]{0,220}(?:req\.body|request\.body|params|query)/gi,reason:'Merging attacker-controlled objects into application state can enable prototype pollution or unintended property overrides.',fix:'Allowlist accepted keys and use merge utilities that safely handle __proto__, constructor, and prototype keys.'},
    {id:'NOSQL-001',category:'Injection',severity:'high',title:'Request object appears to reach a NoSQL filter',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go'],pattern:/(?:find|findOne|findBy|aggregate|updateOne|deleteOne)\s*\([^\n]{0,180}(?:req\.body|request\.body|req\.query|request\.query)/gi,reason:'Passing request objects directly into NoSQL filters can enable operator injection or unexpected query behavior.',fix:'Build query objects from an allowlisted set of fields and validate expected scalar types.'},
    {id:'NOSQL-002',category:'Injection',severity:'medium',title:'Mongo-style operator key appears in request handling',ext:['js','mjs','cjs','ts','tsx','php','py','go'],pattern:/\$where|\$(?:ne|gt|gte|lt|lte|regex|in|nin)\b/gi,reason:'Database operator keys deserve review when they can be influenced by users.',fix:'Strip or reject unexpected operator keys from user-controlled objects and validate schema types.'},
    {id:'IFRAME-001',category:'Browser Isolation',severity:'medium',title:'Dynamic iframe srcdoc content detected',ext:['html','htm','js','mjs','cjs','ts','tsx','jsx'],pattern:/\bsrcdoc\s*=|\.srcdoc\s*=/gi,reason:'srcdoc creates a document from a string and is dangerous when the content is not fully trusted.',fix:'Avoid user-controlled srcdoc. If sandboxed documents are required, use a restrictive sandbox and safe content generation.'},
    {id:'IFRAME-002',category:'Browser Isolation',severity:'low',title:'Iframe sandbox attribute not detected on an embedded frame',ext:['html','htm','php'],pattern:/<iframe\b(?=[^>]*\bsrc\s*=)(?![^>]*\bsandbox\b)[^>]*>/gi,reason:'Untrusted embedded documents benefit from explicit sandboxing.',fix:'Assess whether the iframe content is trusted and add a restrictive sandbox policy when appropriate.'},
    {id:'SOURCE-MAP-001',category:'Information Exposure',severity:'low',title:'Source map file included in project output',ext:['map'],pattern:/"sourcesContent"\s*:/gi,reason:'Source maps can expose original source, comments, and internal paths in production.',fix:'Do not publish source maps publicly unless intentionally required; keep private maps in a controlled artifact store.'},
    {id:'ENV-PUBLIC-001',category:'Secrets',severity:'high',title:'Public build-time variable looks secret-bearing',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/\b(?:NEXT_PUBLIC|VITE|PUBLIC|EXPO_PUBLIC)_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY)\b/gi,reason:'Public-prefixed build variables are typically bundled into client code and should not contain server secrets.',fix:'Remove secret material from public-prefixed variables. Keep secrets on trusted server/edge code.'},
    {id:'APIKEY-001',category:'Secrets',severity:'medium',title:'Generic API-key parameter exposed in client code',ext:['html','htm','js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/(?:apiKey|api_key|clientSecret|privateKey)\s*[:=]\s*[\"\'][^\"\'\n]{10,}[\"\']/gi,reason:'Client-delivered API keys may be extractable and abused unless they are intentionally public and restricted.',fix:'Determine whether the credential is actually secret. Move sensitive credentials server-side and rotate any exposed ones.'},
    {id:'DEBUG-ENDPOINT-001',category:'Information Exposure',severity:'medium',title:'Debug or metrics endpoint path detected',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:[\"\'`]\/(?:debug|metrics|actuator|healthz|internal|admin)[\"\'`])/gi,reason:'Operational endpoints can expose internal state if they are not intentionally public.',fix:'Confirm the endpoint is required, return only necessary data, and protect internal endpoints with appropriate network or authorization controls.'},
    {id:'GRAPHQL-001',category:'API Security',severity:'low',title:'GraphQL introspection-related setting detected',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java'],pattern:/introspection\s*[:=]\s*true/gi,reason:'Introspection can disclose schema details in production APIs when unrestricted.',fix:'Disable introspection in production when it is not required, or enforce authentication/authorization around the endpoint.'},
    {id:'CORS-003',category:'CORS',severity:'low',title:'Wildcard Access-Control-Allow-Origin detected',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/Access-Control-Allow-Origin\s*[:=]\s*[\"\']\*[\"\']/gi,reason:'Wildcard CORS exposes a response to any requesting origin when other controls permit access.',fix:'Use an explicit origin allowlist for sensitive APIs. Keep wildcard CORS only for deliberately public, non-sensitive resources.'},
    {id:'HEADER-PROBE-001',category:'Information Exposure',severity:'low',title:'Server technology fingerprinting header configured',ext:['js','mjs','cjs','ts','tsx','jsx','php'],pattern:/X-Powered-By\s*[:=]/gi,reason:'Technology fingerprinting headers provide extra information to automated scanners.',fix:'Disable unnecessary framework/version fingerprinting headers in production.'},
    {id:'HTML-DATA-001',category:'Privacy',severity:'low',title:'Sensitive-looking data placed in HTML data attributes',ext:['html','htm','php'],pattern:/data-(?:token|secret|password|ssn|phone|email|address)\s*=\s*[\"\'][^\"\']+[\"\']/gi,reason:'Data attributes are visible to client-side JavaScript and anyone who can inspect the page.',fix:'Do not embed secrets or unnecessary personal data in HTML sent to the browser.'},
    {id:'SECRET-URL-001',category:'Secrets',severity:'medium',title:'Credential-like value embedded in a URL',ext:['html','htm','js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/(?:https?:\/\/[^\s"'<>]+[?&](?:token|api[_-]?key|secret|password)=)[^&\s"'<>]{8,}/gi,reason:'Credentials in URLs can leak through browser history, referrers, logs, analytics, and monitoring systems.',fix:'Use headers or secure request bodies for secrets; invalidate tokens that may already have been exposed.'},
    {id:'AUTH-006',category:'Authentication',severity:'medium',title:'Session identifier appears in a URL parameter',ext:['html','htm','js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/[?&](?:session|sid|session_id|auth_token)=/gi,reason:'Session identifiers in URLs are more likely to leak through logs, history, analytics, and referrers.',fix:'Use secure cookie-based or header-based session transport rather than URL parameters.'},
    {id:'CSS-001',category:'Browser Security',severity:'low',title:'CSS expression-like legacy construct detected',ext:['css','html','htm'],pattern:/expression\s*\(/gi,reason:'Legacy CSS execution constructs should not appear in modern production code.',fix:'Remove the legacy construct and implement the intended behavior with standard CSS or JavaScript.'},
    {id:'HTML-004',category:'Browser Security',severity:'medium',title:'Object/embed element detected',ext:['html','htm','php'],pattern:/<(?:object|embed)\b/gi,reason:'Plugin-like embedded content expands the browser attack surface and can behave differently across clients.',fix:'Remove legacy embeds when possible; otherwise tightly control sources and permissions.'},
    {id:'JS-PROTO-001',category:'Injection',severity:'medium',title:'Dynamic property access uses __proto__',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/[\[\.]__proto__\]?/gi,reason:'Direct __proto__ manipulation can enable prototype pollution and unexpected object behavior.',fix:'Avoid __proto__ writes. Use Object.create(null) or safe property assignment with allowlisted keys.'},
    {id:'JS-FETCH-CREDENTIALS-001',category:'Browser Security',severity:'low',title:'Fetch configured with include credentials',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/credentials\s*:\s*[\"\']include[\"\']/gi,reason:'Cross-origin credentialed fetches require deliberate CORS and trust-boundary configuration.',fix:'Confirm the destination is trusted and CORS, cookie SameSite, and authorization policies are aligned.'},
    {id:'AUTH-007',category:'Authentication',severity:'low',title:'Client-side route guard detected',ext:['js','mjs','cjs','ts','tsx','jsx','ts','vue','svelte'],pattern:/(?:protectedRoute|privateRoute|requireAuth|isAuthenticated)\s*[=:]/gi,reason:'Client-side route guards do not enforce authorization by themselves.',fix:'Treat browser route guards as UX only and enforce authentication/authorization on the server or trusted edge.'},
    {id:'ERROR-002',category:'Information Exposure',severity:'medium',title:'Full request body appears to be returned in an error response',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/(?:res\.(?:json|send)|response\.(?:json|send)|return)[^\n]{0,180}(?:req\.body|request\.body)/gi,reason:'Echoing arbitrary request payloads can reflect sensitive or attacker-controlled data back to clients.',fix:'Return only the minimal safe error details required by the client.'},
    {id:'LOG-002',category:'Information Exposure',severity:'low',title:'Cookie header logged',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/\b(?:console\.log|logger\.(?:info|debug|warn|error)|print\s*\()[^\n]{0,160}\bcookie\b/gi,reason:'Cookie headers can contain session secrets and should not be logged verbatim.',fix:'Redact or omit Cookie/Set-Cookie headers from logs.'},
    {id:'FRAMEWORK-XSS-001',category:'Cross-Site Scripting',severity:'high',title:'React raw HTML rendering detected',ext:['js','mjs','cjs','ts','tsx','jsx'],pattern:/dangerouslySetInnerHTML\s*=|dangerouslySetInnerHTML\s*:/gi,reason:'React bypasses its normal text escaping for dangerouslySetInnerHTML.',fix:'Prefer normal JSX text rendering. When raw HTML is required, sanitize trusted/allowlisted content before passing it to the sink.'},
    {id:'FRAMEWORK-XSS-002',category:'Cross-Site Scripting',severity:'high',title:'Vue raw HTML rendering detected',ext:['vue','js','ts'],pattern:/\bv-html\s*=|\bv-html\s*:/gi,reason:'v-html renders HTML directly into the DOM.',fix:'Prefer text interpolation. Sanitize any HTML content that truly must be rendered.'},
    {id:'FRAMEWORK-XSS-003',category:'Cross-Site Scripting',severity:'high',title:'Svelte raw HTML block detected',ext:['svelte','js','ts'],pattern:/\{@html\s+/gi,reason:'Svelte {@html} inserts raw HTML into the DOM.',fix:'Prefer escaped text rendering. Sanitize HTML with an allowlist sanitizer before using {@html}.'},
    {id:'FRAMEWORK-XSS-004',category:'Cross-Site Scripting',severity:'high',title:'Server template safe-filter detected',ext:['py','html','htm','jinja','jinja2'],pattern:/\|safe\b|mark_safe\s*\(|Markup\s*\(/gi,reason:'Template safe filters bypass normal output escaping and can become XSS sinks.',fix:'Remove the safe bypass or ensure the value has been sanitized against a strict allowlist before rendering.'},
    {id:'SECURITY-JWT-001',category:'Authentication',severity:'high',title:'JWT algorithm explicitly allows none',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/[\"\'`]alg[\"\'`]\s*[:=]\s*[\"\']none[\"\']/gi,reason:'The none algorithm disables cryptographic signing and must not be accepted for authenticated tokens.',fix:'Explicitly allow only the algorithm(s) your trust boundary requires and verify the signature.'},
    {id:'SECURITY-JWT-002',category:'Authentication',severity:'medium',title:'JWT verification uses an algorithm list that appears too broad',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/(?:algorithms|allowedAlgorithms)\s*[:=]\s*\[[^\]]{0,180}(?:none|HS256|RS256|ES256)[^\]]{0,180}(?:none|HS256|RS256|ES256)/gi,reason:'Multiple unrelated algorithms in token verification configuration can create algorithm-confusion risk if key types are not constrained.',fix:'Use a narrow explicit algorithm policy matched to the key type and issuer.'},
    {id:'BROWSER-DOM-001',category:'Cross-Site Scripting',severity:'medium',title:'URL fragment written to a DOM sink',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/(?:location\.hash|location\.search|URLSearchParams)[^\n]{0,220}(?:innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|v-html|srcdoc)/gi,reason:'Browser URL data is attacker-controllable and should be treated as untrusted input.',fix:'Validate/encode the value before rendering or use safe text/DOM APIs.'},
    {id:'DOM-URL-001',category:'Cross-Site Scripting',severity:'medium',title:'User-controlled URL assigned to DOM URL sink',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/(?:location\.search|location\.hash|URLSearchParams)[^\n]{0,180}(?:script\.src|iframe\.src|img\.src|link\.href|window\.location)/gi,reason:'URL-derived data assigned to navigational or resource sinks can enable unexpected navigation or script/resource loading.',fix:'Validate scheme, origin, and expected path before assigning the value to a URL sink.'},
    {id:'POSTMSG-003',category:'Cross-Window Messaging',severity:'medium',title:'Message payload inserted into a DOM sink',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/(?:message|MessageEvent)[^\n]{0,220}(?:event\.data|e\.data)[^\n]{0,220}(?:innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML)/gi,reason:'Cross-window message payloads are untrusted unless the sender and content are validated.',fix:'Validate origin and schema, then render as text or sanitize trusted HTML before insertion.'},
    {id:'RUNTIME-001',category:'Injection',severity:'high',title:'Dynamic import target appears user-controlled',ext:['js','mjs','cjs','ts','tsx','jsx'],pattern:/\bimport\s*\([^\n]{0,180}(?:req\.|request\.|query|params|body|input|location)/gi,reason:'Dynamic module loading from attacker-controlled paths can expose unintended code or filesystem resolution behavior.',fix:'Use an allowlisted module map rather than importing arbitrary paths.'},
    {id:'RUNTIME-002',category:'Injection',severity:'medium',title:'Dynamic require target appears user-controlled',ext:['js','mjs','cjs','ts','tsx','jsx'],pattern:/\brequire\s*\([^\n]{0,160}(?:req\.|request\.|query|params|body|input)/gi,reason:'Dynamic require paths derived from input deserve strict allowlisting.',fix:'Map user-visible identifiers to fixed modules instead of requiring arbitrary paths.'},
    {id:'API-INPUT-001',category:'Input Validation',severity:'low',title:'Request body used without an obvious schema validation call',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/(?:req\.body|request\.body)[^\n]{0,220}(?:db\.|query|execute|fetch|res\.|response\.)/gi,reason:'Request bodies reaching core operations should be validated for shape, type, bounds, and business rules.',fix:'Validate at the trust boundary with a schema and reject unexpected fields/types before use.'},
    {id:'API-INPUT-002',category:'Input Validation',severity:'low',title:'Query parameter used in core operation without an obvious type check',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','go','java','rb'],pattern:/(?:req\.query|request\.query|searchParams\.get)\([^\n]{0,120}\)[^\n]{0,180}(?:db\.|query|execute|fetch|fs\.|path\.|res\.)/gi,reason:'Query strings arrive as untrusted text and should be parsed and constrained before use.',fix:'Parse and validate expected primitive types and lengths before the value reaches business logic or a sensitive sink.'},
    {id:'SECRET-HTML-001',category:'Secrets',severity:'medium',title:'Secret-looking value inside HTML comment',ext:['html','htm','php','vue','svelte'],pattern:/<!--[^>]{0,260}(?:api[_-]?key|token|secret|password|private[_-]?key)[^>]{0,260}-->/gi,reason:'Comments are shipped to the client and can expose credentials or internal notes.',fix:'Remove sensitive comments and rotate any credential that was exposed.'},
    {id:'SOURCE-DEBUG-001',category:'Information Exposure',severity:'low',title:'Source/debug artifact referenced by HTML',ext:['html','htm','php'],pattern:/<(?:script|link|source|a)\b[^>]+(?:src|href)\s*=\s*[\"\'][^\"\']+\.(?:map|log|bak|old|orig)(?:\?[^\"\']*)?[\"\']/gi,reason:'Debug or backup artifacts can expose source or operational details when publicly linked.',fix:'Remove artifact references from production output and keep diagnostics out of the public web root.'},
    {id:'HEADER-COOP-001',category:'Browser Isolation',severity:'low',title:'Cross-Origin-Opener-Policy not evident',ext:['html','htm','php'],projectWide:true,absence:{anchor:/<head\b/i,absent:/Cross-Origin-Opener-Policy/i},reason:'Cross-Origin-Opener-Policy can isolate browsing contexts for applications that handle sensitive cross-origin interactions.',fix:'Assess whether COOP is appropriate for the application and deployment model; this is not required for every site.'},
    {id:'HEADER-COEP-001',category:'Browser Isolation',severity:'low',title:'Cross-Origin-Embedder-Policy not evident',ext:['html','htm','php'],projectWide:true,absence:{anchor:/<head\b/i,absent:/Cross-Origin-Embedder-Policy/i},reason:'Cross-Origin-Embedder-Policy can strengthen cross-origin isolation in applications that need it.',fix:'Assess COEP alongside CORP/CORS and application dependencies before enabling it.'},

    {id:'DESER-001',category:'Deserialization',severity:'high',title:'Unsafe Python pickle deserialization',ext:['py'],pattern:/\bpickle\.(?:loads|load)\s*\(/gi,reason:'Python pickle can execute attacker-controlled object behavior during deserialization.',fix:'Do not deserialize untrusted pickle data. Use a safe data format such as JSON with strict schema validation.'},
    {id:'DESER-002',category:'Deserialization',severity:'medium',title:'Unsafe YAML loader usage detected',ext:['py'],pattern:/\byaml\.(?:load|full_load|unsafe_load)\s*\(/gi,reason:'YAML loaders can construct application objects when given unsafe input.',fix:'Use a safe loader such as yaml.safe_load for untrusted data and validate the resulting structure.'},
    {id:'XXE-001',category:'Injection',severity:'high',title:'XML parser configured without obvious entity hardening',ext:['py','js','mjs','cjs','ts','tsx','java','php','rb','go'],pattern:/(?:XMLParser|DocumentBuilderFactory|SAXParserFactory|etree\.parse|DOMParser)[^\n]{0,260}(?:DOCTYPE|external|entity)/gi,reason:'XML entity processing can expose local resources or create server-side request behavior when untrusted XML is parsed.',fix:'Disable external entities and DTD processing where supported, and use hardened parser settings for untrusted XML.'},
    {id:'TLS-VERIFY-001',category:'Transport',severity:'high',title:'TLS certificate verification disabled',ext:['py','js','mjs','cjs','ts','tsx','php','go','java','rb'],pattern:/(?:verify\s*=\s*False|rejectUnauthorized\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["']?0["']?|checkServerIdentity\s*[:=]\s*\(?.*=>\s*undefined)/gi,reason:'Disabling TLS certificate verification permits man-in-the-middle attacks.',fix:'Restore certificate verification and only use explicit local test exceptions outside production paths.'},
    {id:'CRYPTO-HASH-001',category:'Cryptography',severity:'medium',title:'Weak hash algorithm used for security-sensitive data',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/\b(?:md5|sha1|MD5|SHA1)\b[\s\S]{0,100}(?:password|token|secret|sign|hash)/gi,reason:'MD5 and SHA-1 are inappropriate for many modern security-sensitive uses.',fix:'Use a modern password-hashing API for passwords and a collision-resistant modern hash such as SHA-256 when a general-purpose hash is actually required.'},
    {id:'CRYPTO-KEY-001',category:'Cryptography',severity:'high',title:'Hard-coded cryptographic key material detected',ext:['js','mjs','cjs','ts','tsx','jsx','py','php','java','go','rb'],pattern:/(?:encryptionKey|signingKey|secretKey|aesKey|hmacKey)\s*[:=]\s*["'][^"']{16,}["']/gi,reason:'Long-lived cryptographic keys embedded in source can be extracted and reused.',fix:'Load keys from a trusted server-side secret mechanism and rotate any real key already exposed.'},
    {id:'CRYPTO-IV-001',category:'Cryptography',severity:'medium',title:'Static initialization vector appears hard-coded',ext:['js','mjs','cjs','ts','tsx','jsx','py','php','java','go','rb'],pattern:/(?:iv|initial(?:ization)?Vector)\s*[:=]\s*["'][A-Za-z0-9+/=_-]{8,}["']/gi,reason:'A reused initialization vector can weaken confidentiality for certain encryption modes.',fix:'Generate a fresh cryptographically random IV/nonce for each encryption operation using the algorithm-specific requirements.'},
    {id:'CMD-SHELL-001',category:'Command Injection',severity:'high',title:'Process execution enables shell interpretation',ext:['js','mjs','cjs','ts','tsx','py','php','go','java','rb'],pattern:/(?:shell\s*:\s*true|subprocess\.(?:run|Popen|call)\s*\([^\n]{0,180}shell\s*=\s*True)/gi,reason:'Shell interpretation expands the impact of dynamic process arguments and can turn data into commands.',fix:'Disable shell execution and pass a fixed executable plus separate allowlisted arguments.'},
    {id:'FS-PERM-001',category:'Configuration',severity:'medium',title:'World-writable filesystem permission detected',ext:['py','js','mjs','cjs','ts','tsx','php','go','java','rb','sh'],pattern:/\b(?:chmod|mode)\s*\([^\n]{0,120}(?:0?777|0?666|\"777\"|\'777\')/gi,reason:'World-writable files and directories can permit unintended modification by other principals.',fix:'Use the narrowest filesystem permissions required by the application and review ownership separately.'},
    {id:'REGEX-DOS-001',category:'Denial of Service',severity:'medium',title:'Potentially expensive nested regex detected',ext:['js','mjs','cjs','ts','tsx','jsx','py','php','java','go','rb'],pattern:/\/(?:[^/\n]|\\.)*(?:\([^)]*[+*][^)]*\)|\[[^\]]+[+*])+(?:\+|\*)[^/\n]*\/[gimuys]*/g,reason:'Nested repetition in regular expressions can cause excessive CPU use for adversarial input.',fix:'Simplify the expression, use atomic/possessive constructs where supported, or impose strict input length limits and benchmark worst-case inputs.'},
    {id:'AUTH-RATE-001',category:'Authentication',severity:'low',advisory:true,occurrence:'per-file',title:'Authentication handler lacks an obvious rate-limit boundary',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:login|signin|sign-in|authenticate|verifyPassword|password)\b[^\n]{0,260}(?:req\.body|request\.body|password)/gi,reason:'Credential and login endpoints are common brute-force targets.',fix:'Add rate limiting, abuse controls, and lockout/backoff appropriate to the authentication flow without creating account-enumeration side channels.'},
    {id:'GRAPHQL-DEPTH-001',category:'API Security',severity:'medium',advisory:true,title:'GraphQL API lacks an obvious query-depth/complexity control',ext:['js','mjs','cjs','ts','tsx','jsx','php','py','java'],pattern:/graphql[^\n]{0,260}(?:buildSchema|ApolloServer|express-graphql|GraphQLServer)/gi,reason:'Deep or expensive GraphQL queries can consume disproportionate resources.',fix:'Assess depth/complexity limits, pagination requirements, resolver cost, and rate limits before exposing GraphQL to untrusted clients.'},
    {id:'DOM-XSS-004',category:'Cross-Site Scripting',severity:'medium',title:'React HTML injection escape hatch',ext:['jsx','tsx','js','ts'],pattern:/dangerouslySetInnerHTML\s*=\s*\{?/g,reason:'React HTML injection escape hatches bypass normal output encoding.',fix:'Avoid the escape hatch for untrusted content. Prefer normal text rendering; when rich HTML is required, sanitize it with a well-maintained allowlist sanitizer.'},
    {id:'DOM-XSS-005',category:'Cross-Site Scripting',severity:'medium',title:'Vue raw HTML rendering directive',ext:['vue'],pattern:/\bv-html\s*=|\bv-html\b/g,reason:'Vue raw HTML rendering bypasses normal HTML escaping.',fix:'Prefer normal interpolation. When raw HTML is required, sanitize the value before binding it.'},
    {id:'DOM-XSS-006',category:'Cross-Site Scripting',severity:'medium',title:'Svelte raw HTML rendering block',ext:['svelte'],pattern:/\{@html\b/g,reason:'Svelte raw HTML rendering bypasses normal HTML escaping.',fix:'Prefer normal text rendering or sanitize the HTML with a well-maintained allowlist sanitizer before rendering.'},
  ];

  const EXTRA_RULES = [
    {id:'ACCESS-IDOR-001',category:'Access Control',severity:'medium',advisory:true,title:'Object lookup uses a request ID without a visible ownership check',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/\b(?:findById|findOne|findByPk|find\s*\(|get\s*\(|SELECT\s+\*[^;\n]{0,120}WHERE[^;\n]{0,140})[^;\n]{0,180}(?:req(?:uest)?\.(?:params|query)|request\.(?:args|query|params))/gi,reason:'Looking up a record by an ID is not automatically unsafe, but it deserves a check that the caller is allowed to access that record.',fix:'Verify ownership or role-based permission on the server before returning or changing the record. Do not rely on a hidden UI control.',confidenceBase:'low',guard:/owner|ownership|authorize|authorization|canAccess|permission|role|isAdmin|requireAuth/i},
    {id:'ACCESS-IDOR-002',category:'Access Control',severity:'medium',advisory:true,title:'A request-controlled record ID reaches a data operation',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:req(?:uest)?\.(?:params|query)|request\.(?:args|query|params))\.[A-Za-z_$][\w$]*(?=[^\n]{0,220}(?:findById|findOne|findByPk|UPDATE|DELETE|SELECT))/gi,reason:'A record identifier supplied by the request can only be safe if the server checks whether that caller may access the record.',fix:'Add a server-side authorization/ownership check before the data operation.',confidenceBase:'low'},
    {id:'ACCESS-ADMIN-001',category:'Access Control',severity:'medium',advisory:true,title:'An admin decision appears to rely on browser-side state',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/\b(?:isAdmin|isAdministrator|role)\s*(?:===?|!==?)\s*["']admin["']/gi,reason:'Anything in browser JavaScript can be modified by the visitor and should not be the final authority for privileged actions.',fix:'Enforce the admin role on the server for every privileged operation. Keep the browser check only as a UI convenience.',confidenceBase:'low'},
    {id:'AUTH-RESET-001',category:'Authentication',severity:'high',advisory:true,title:'A password-reset or verification token may use a predictable value',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/\b(?:resetToken|passwordResetToken|verificationToken|resetCode|verificationCode)\b\s*=\s*(?:Date\.now\s*\(|new\s+Date\s*\(|Math\.random\s*\()/gi,reason:'Reset and verification credentials need to be unpredictable. Time and Math.random are not suitable security token generators.',fix:'Generate high-entropy random tokens with the platform cryptographic API and give them short lifetimes.',confidenceBase:'high'},
    {id:'AUTH-RESET-002',category:'Authentication',severity:'high',advisory:true,title:'A password-reset or verification token may be written to logs',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/\b(?:console\.log|logger\.(?:info|debug|warn|error)|print)\s*\([^\n]{0,180}\b(?:resetToken|passwordResetToken|verificationToken|resetCode|verificationCode)\b/gi,reason:'Reset tokens are credentials. Logging them can turn a temporary secret into a credential available to anyone who can read the logs.',fix:'Remove the token from logs and record only a safe identifier or event.',confidenceBase:'high'},
    {id:'AUTH-CREDENTIAL-001',category:'Authentication',severity:'high',advisory:true,title:'A password appears to be persisted without an obvious password-hashing boundary',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:password|passwd|pwd)\s*[:=]\s*(?:req(?:uest)?\.(?:body|form)|request\.(?:body|form)|password)\b[^\n]{0,180}(?:\.save\(|\.create\(|\.insert\(|INSERT\s+INTO|UPDATE\s+)/gi,reason:'Passwords should normally be turned into a dedicated password hash before they are stored. The pattern alone cannot prove that hashing is absent.',fix:'Trace the value into storage and confirm it passes through a strong password-hashing function such as Argon2id, scrypt, or bcrypt before persistence.',confidenceBase:'low'},
    {id:'API-AUTH-001',category:'Access Control',severity:'medium',advisory:true,occurrence:'per-file',title:'A state-changing API route does not show an obvious authorization boundary nearby',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],check:(text)=>{const hits=[];const rx=/\b(?:app|router|server)\.(?:post|put|patch|delete)\s*\(\s*["'][^"']+["']/gi;for(const m of allMatches(rx,text,6)){const ctx=text.slice(m.index,Math.min(text.length,m.index+650));if(/login|logout|webhook|health|public|signup|sign-up|register/i.test(ctx))continue;if(!/(?:requireAuth|authenticate|isAuthenticated|verifyToken|verifyJwt|authorization|permissions?|role|csrf|Origin|Referer)/i.test(ctx))hits.push({index:m.index});}return hits;},reason:'A state-changing endpoint often needs a server-side identity and permission check. This scan cannot know which routes are intentionally public.',fix:'Confirm the route is intentionally public. Otherwise enforce authentication and the specific permission required for the action.',confidenceBase:'low'},
    {id:'API-AUTH-002',category:'Access Control',severity:'medium',advisory:true,occurrence:'per-file',title:'A delete endpoint has no obvious permission check nearby',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/\b(?:app|router|server)\.delete\s*\(\s*["'][^"']+["'][\s\S]{0,420}\{/gi,reason:'Delete operations are sensitive and usually require explicit authentication and authorization.',fix:'Require authentication and check that the caller is allowed to delete the targeted resource.',confidenceBase:'low',guard:/requireAuth|authenticate|verifyToken|authorization|authorize|permission|role|isAdmin/i},
    {id:'API-INPUT-003',category:'API Security',severity:'low',advisory:true,occurrence:'per-file',title:'JSON request parsing has no visible size limit',ext:['js','mjs','cjs','ts','tsx'],pattern:/\bexpress\.json\s*\(\s*\)/g,reason:'An unlimited JSON body can consume excessive memory when clients send unusually large requests.',fix:'Set an explicit request-body limit appropriate for the endpoints you expose.',confidenceBase:'low'},
    {id:'API-INPUT-004',category:'API Security',severity:'low',advisory:true,occurrence:'per-file',title:'Multipart upload handling has no obvious size limit',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/\b(?:multer|formidable|busboy)\s*\(\s*\)/gi,reason:'Multipart parsers without a visible size boundary can allow oversized requests to consume server resources.',fix:'Set upload/request limits and reject oversized bodies before expensive processing.',confidenceBase:'low'},
    {id:'SSRF-002',category:'SSRF',severity:'high',advisory:true,title:'A server-side network request may use a URL supplied by the client',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post|request)|httpx\.(?:get|post)|urllib\.request\.urlopen|got\s*\()[^\n]{0,220}(?:req(?:uest)?\.(?:query|body|params)|request\.(?:args|json|form|query)|userUrl|targetUrl|url)/gi,reason:'If a visitor can choose the destination of a server-side network request, the server may be tricked into contacting internal services or other protected systems.',fix:'Allowlist destinations, validate the scheme and hostname, block private/link-local ranges, and resolve/re-check the final destination before connecting.',confidenceBase:'medium'},
    {id:'SSRF-003',category:'SSRF',severity:'medium',advisory:true,title:'A download, proxy, or image fetch feature accepts a dynamic URL',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:download|proxy|image|thumbnail|fetchUrl|remoteUrl)\b[^\n]{0,220}(?:req(?:uest)?\.(?:query|body|params)|request\.(?:args|json|form|query)|https?:\/\/)/gi,reason:'Features that fetch remote URLs are commonly abused as server-side request proxies.',fix:'Restrict outbound destinations to trusted hosts or controlled resources and validate redirects as well as the first URL.',confidenceBase:'low'},
    {id:'PATH-003',category:'Path Traversal',severity:'high',advisory:true,title:'A request value may directly choose a file sent by the server',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:sendFile|send_file|readFile|readFileSync|open|File\.readAllBytes)\s*\([^\n]{0,220}(?:req(?:uest)?\.(?:query|params)|request\.(?:args|query|params))/gi,reason:'A request-controlled path can sometimes escape the directory the developer intended.',fix:'Resolve against a fixed root directory, reject traversal, and enforce an allowlist of files or identifiers rather than accepting arbitrary paths.',confidenceBase:'medium'},
    {id:'PATH-004',category:'Path Traversal',severity:'high',title:'An archive may be extracted without a visible path-safety boundary',ext:['py','java','php','rb','go'],pattern:/(?:ZipFile|TarFile|ZipArchive|Archive)\b[^\n]{0,220}\.(?:extractall|extractTo|unpack|extract)\s*\(/gi,reason:'Archive entries can contain paths that escape the intended extraction folder if extraction is not checked first.',fix:'Validate every archive member path before extraction and reject absolute paths or paths that resolve outside the destination root.',confidenceBase:'medium'},
    {id:'UPLOAD-002',category:'File Uploads',severity:'high',advisory:true,title:'An upload appears to trust the browser-provided content type',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:mimetype|content-type|Content-Type)\b[^\n]{0,220}(?:upload|file|req(?:uest)?\.files|request\.files)[^\n]{0,220}(?:writeFile|write_bytes|save\(|createWriteStream)/gi,reason:'The browser chooses the declared content type. That value should not be the only proof that an uploaded file is safe.',fix:'Validate the file type using trusted server-side inspection, enforce a small allowlist, limit size, and keep the upload out of executable paths.',confidenceBase:'low'},
    {id:'UPLOAD-003',category:'File Uploads',severity:'high',title:'Uploaded data may be stored inside a public web directory',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:UPLOAD|upload|uploads)[^\n]{0,180}(?:public|static|wwwroot|htdocs|webroot|\/public\/)[^\n]{0,180}(?:write|save|mkdir|move|copy)/gi,reason:'If uploaded files are directly web-accessible, a dangerous file can become active content or be served as if it were trusted site content.',fix:'Keep uploads outside public/executable directories or serve them through a controlled download path.',confidenceBase:'medium'},
    {id:'UPLOAD-004',category:'File Uploads',severity:'medium',advisory:true,title:'Uploaded archives may be processed without visible entry-count or expansion limits',ext:['py','js','mjs','cjs','ts','php','java','go','rb'],pattern:/(?:zipfile|ZipFile|tarfile|TarFile|unzip|extractall|extractTo)\b[^\n]{0,220}(?:upload|file|request|req)/gi,reason:'Compressed archives can expand into huge numbers or sizes of files and consume server resources.',fix:'Limit archive size, member count, total expanded size, and extraction time before processing.',confidenceBase:'low'},
    {id:'DOM-XSS-007',category:'Cross-Site Scripting',severity:'medium',advisory:true,title:'HTML is built directly from a network response',ext:['js','mjs','cjs','ts','tsx'],pattern:/\.(?:innerHTML|outerHTML)\s*=\s*[^\n]{0,120}(?:response|res|fetch|json\(|data\.)/gi,reason:'Data received from an API or other remote source becomes active HTML without an obvious safety boundary.',fix:'Render untrusted values as text or sanitize the specific HTML fields with a maintained allowlist before insertion.',confidenceBase:'low'},
    {id:'DOM-XSS-008',category:'Cross-Site Scripting',severity:'high',advisory:true,title:'A page replaces its HTML with application data',ext:['js','mjs','cjs','ts','tsx','jsx'],pattern:/(?:document\.body|document\.documentElement|document\.querySelector\([^\n]{0,80}\))\.(?:innerHTML|outerHTML)\s*=\s*[^\n]{0,180}(?:data|response|result|user|input)/gi,reason:'Replacing a large section of the document with data can turn attacker-controlled values into active markup.',fix:'Build the affected DOM nodes explicitly or sanitize every untrusted HTML value before insertion.',confidenceBase:'medium'},
    {id:'DOM-URL-002',category:'Browser Security',severity:'medium',advisory:true,title:'A browser window may open a destination chosen by the user',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/\bwindow\.open\s*\(\s*(?:[^,\n]{0,80})(?:location|searchParams|query|userUrl|next|redirectUrl)/gi,reason:'A user-controlled destination can be used for unwanted navigation or phishing flows.',fix:'Allow only expected schemes and trusted destinations before calling window.open.',confidenceBase:'low'},
    {id:'POSTMSG-004',category:'Cross-Window Messaging',severity:'high',advisory:true,title:'Browser message data may reach an HTML sink',ext:['js','mjs','cjs','ts','tsx','jsx'],flow:{maxDistance:900,allowReverse:true,sources:[/(?:message|event|evt|e)\s*\.data/i],sinks:[/\.innerHTML\b/i,/\.outerHTML\b/i,/insertAdjacentHTML\s*\(/i]},reason:'Messages from another window can contain attacker-controlled data and should not automatically become HTML.',fix:'Check event.origin against a strict allowlist and render message data safely.',confidenceBase:'medium'},
    {id:'POSTMSG-005',category:'Cross-Window Messaging',severity:'medium',advisory:true,title:'Sensitive data may be posted to any website',ext:['js','mjs','cjs','ts','tsx','jsx'],pattern:/\.postMessage\s*\([^\n]{0,220},\s*["']\*["']/gi,reason:'A wildcard target origin allows the message to be received by any origin that can obtain the window reference.',fix:'Use the exact trusted target origin instead of "*" whenever the message contains sensitive data.',confidenceBase:'low'},
    {id:'TEMPLATE-SOURCE-001',category:'Injection',severity:'high',advisory:true,title:'A server template appears to be built from request data',ext:['py','php','js','ts','rb'],pattern:/(?:Template|render_template_string|new\s+Function|ejs\.render|Handlebars\.compile)\s*\([^\n]{0,220}(?:req(?:uest)?\.(?:body|query|params)|request\.(?:args|json|form|query))/gi,reason:'Letting visitors choose template source can turn data into code that executes on the server or during rendering.',fix:'Keep templates fixed in trusted application code. Pass visitor data as template variables and escape output appropriately.',confidenceBase:'high'},
    {id:'TEMPLATE-002',category:'Injection',severity:'medium',advisory:true,title:'A template is compiled dynamically at runtime',ext:['js','mjs','cjs','ts','tsx','py','php','rb'],pattern:/(?:ejs\.render|Handlebars\.compile|Mustache\.render|Template)\s*\([^\n]{0,220}\)/gi,reason:'Dynamic template compilation deserves a check that the template source is controlled by the application rather than a visitor.',fix:'Keep template source trusted and treat all external values as data only.',confidenceBase:'low'},
    {id:'DESER-003',category:'Deserialization',severity:'high',title:'Dynamic JavaScript execution through a VM API',ext:['js','mjs','cjs','ts','tsx'],pattern:/\bvm\.(?:runInNewContext|runInThisContext|runInContext)\s*\(/gi,reason:'Node VM APIs execute JavaScript code and are not a general-purpose sandbox for attacker-controlled code.',fix:'Do not execute untrusted JavaScript. Replace the dynamic code path with data validation and explicit operations.',confidenceBase:'high'},
    {id:'DESER-004',category:'Deserialization',severity:'high',title:'PHP unserialize may process attacker-controlled data',ext:['php'],pattern:/\bunserialize\s*\(/gi,reason:'PHP object deserialization can invoke gadget chains when given attacker-controlled serialized data.',fix:'Prefer JSON or another data-only format for untrusted input and validate the expected fields.',confidenceBase:'high'},
    {id:'XXE-002',category:'Injection',severity:'medium',advisory:true,title:'An XML parser may be handling untrusted input without a visible hardened parser',ext:['py','java','php','go','rb'],pattern:/(?:lxml\.etree\.fromstring|ET\.fromstring|DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\))/gi,reason:'XML parser defaults vary by library and version. Untrusted XML should be parsed with external entities and network access disabled.',fix:'Use the library’s hardened parser configuration and explicitly disable external entities and DTD processing.',confidenceBase:'low'},
    {id:'CRYPTO-ECB-001',category:'Cryptography',severity:'medium',advisory:true,title:'Electronic Codebook mode appears in the project',ext:['js','mjs','cjs','ts','tsx','py','php','java','go','rb'],pattern:/\b(?:AES|Cipher|Crypto|CryptoJS)[^\n]{0,100}\b(?:ECB|MODE_ECB)\b/gi,reason:'ECB encryption does not hide repeated plaintext patterns and is generally unsuitable for normal message encryption.',fix:'Use an authenticated encryption mode such as AES-GCM or the secure mode recommended by the library.',confidenceBase:'medium'},
    {id:'CRYPTO-RNG-001',category:'Cryptography',severity:'high',advisory:true,title:'A security-sensitive value may use Math.random',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/\b(?:token|session|secret|code|otp|nonce|key|passwordReset)\b[^\n]{0,120}=\s*[^\n]{0,80}\bMath\.random\s*\(/gi,reason:'Math.random is not a cryptographic random source and can be unsuitable for credentials or security tokens.',fix:'Use crypto.getRandomValues, crypto.randomUUID, or the equivalent server-side cryptographic API.',confidenceBase:'high'},
    {id:'CRYPTO-JWT-001',category:'Authentication',severity:'medium',advisory:true,title:'JWT verification does not show an explicit algorithm policy',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/\b(?:jwt|jsonwebtoken)\.verify\s*\([^\n]{0,220}\)/gi,reason:'JWT verification should explicitly restrict acceptable algorithms and validate issuer, audience, and lifetime where applicable.',fix:'Set an explicit algorithms allowlist and validate the claims required by your authentication design.',confidenceBase:'low'},
    {id:'CRYPTO-CREDENTIAL-001',category:'Cryptography',severity:'medium',advisory:true,title:'A very short JWT or signing secret appears in source',ext:['js','mjs','cjs','ts','tsx','py','php','java','go','rb'],pattern:/\b(?:jwtSecret|jwt_secret|signingSecret|secret)\s*[:=]\s*["'][^"']{1,15}["']/gi,reason:'Short signing secrets are easier to guess or brute-force and should not be embedded in source.',fix:'Use a strong random secret stored outside source control and rotate any real secret already exposed.',confidenceBase:'low'},
    {id:'HEADERS-004',category:'Headers',severity:'medium',advisory:true,title:'The configured Content Security Policy allows unsafe script execution',ext:['conf','config','ini','txt','html','htm','php'],pattern:/Content-Security-Policy[^\n]{0,500}\b(?:unsafe-inline|unsafe-eval)\b/gi,reason:'unsafe-inline and unsafe-eval weaken the protection a Content Security Policy can provide.',fix:'Replace inline/eval-based script execution with nonces, hashes, or external scripts where practical.',confidenceBase:'medium'},
    {id:'HEADERS-005',category:'Headers',severity:'low',advisory:true,title:'The server advertises its software through a response header',ext:['conf','config','ini','txt','php','py','js','ts'],pattern:/(?:X-Powered-By\s*[:=]|app\.disable\s*\(\s*["']x-powered-by["']\s*)/gi,reason:'Software-identifying headers give attackers a little more information about the stack.',fix:'Remove unnecessary technology-identifying response headers at the server or framework layer.',confidenceBase:'low'},
    {id:'HEADERS-006',category:'Headers',severity:'medium',advisory:true,title:'Authenticated responses may be marked publicly cacheable',ext:['conf','config','ini','txt','js','ts','php','py','go','java','rb'],pattern:/Cache-Control[^\n]{0,160}\bpublic\b[^\n]{0,220}(?:session|auth|token|account|profile|private)/gi,reason:'Public caching can accidentally share personalized or authenticated responses between users.',fix:'Review authenticated responses and use private/no-store directives where shared caching would be unsafe.',confidenceBase:'low'},
    {id:'HTTP-003',category:'Transport',severity:'medium',advisory:true,title:'An API request uses a hard-coded HTTP address',ext:['js','mjs','cjs','ts','tsx','jsx','vue','svelte'],pattern:/\b(?:fetch|axios\.(?:get|post|request)|XMLHttpRequest|WebSocket)\b[^\n]{0,80}["']http:\/\//gi,reason:'An unencrypted API endpoint can expose requests to interception or manipulation.',fix:'Use HTTPS for production endpoints and avoid mixed-content connections.',confidenceBase:'medium'},
    {id:'INFO-STACK-001',category:'Information Exposure',severity:'medium',advisory:true,title:'A stack trace appears to be sent back to the client',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/(?:stack|traceback|format_exc)\b[^\n]{0,180}(?:res\.json|jsonify|return\s+Response|response\.)/gi,reason:'Stack traces can reveal filesystem paths, library versions, code structure, and other internal details.',fix:'Return a generic error to the client and keep detailed traces in protected server logs.',confidenceBase:'medium'},
    {id:'INFO-DIR-001',category:'Information Exposure',severity:'low',advisory:true,title:'A directory listing operation appears near a response path',ext:['py','js','mjs','cjs','ts','php','go','java','rb'],pattern:/(?:os\.listdir|readdir|readDir|Directory\.GetFiles|glob\.glob)\s*\([^\n]{0,160}\)[^\n]{0,220}(?:res\.|response|return|json|send\()/gi,reason:'Returning a raw directory listing can reveal filenames and internal structure that visitors did not need to see.',fix:'Expose only the specific files or resources the feature needs and enforce authorization.',confidenceBase:'low'},
    {id:'DEBUG-002',category:'Information Exposure',severity:'low',advisory:true,title:'Verbose server logging may remain enabled in production',ext:['py','js','mjs','cjs','ts','tsx','php','go','java','rb'],pattern:/(?:app\.run|uvicorn\.run|logger\.|logging\.)[^\n]{0,160}\b(?:debug|trace)\b/gi,reason:'Verbose logs can contain secrets, identifiers, or internal implementation details.',fix:'Use an appropriate production log level and confirm sensitive fields are redacted.',confidenceBase:'low'},
    {id:'DEPEND-006',category:'Supply Chain',severity:'low',advisory:true,title:'A dependency is fetched from a Git repository during installation',ext:['json','yaml','yml','toml','txt'],pattern:/["'][^"']+["']\s*:\s*["'](?:git\+https?:\/\/|https?:\/\/github\.com\/)[^"']+["']/gi,reason:'Git-based dependencies can change outside normal package release controls and should be trusted deliberately.',fix:'Prefer a released package version and a lockfile when practical; pin an immutable revision if a Git dependency is truly required.',confidenceBase:'low'},
    {id:'DEPEND-007',category:'Supply Chain',severity:'medium',advisory:true,title:'A package source uses plain HTTP',ext:['json','yaml','yml','toml','txt'],pattern:/["'][^"']+["']\s*:\s*["']http:\/\/[^"']+["']/gi,reason:'Downloading packages over plain HTTP exposes the dependency to tampering in transit.',fix:'Use HTTPS or a trusted package registry with transport security.',confidenceBase:'medium'},
    {id:'INPUT-URL-001',category:'Input Validation',severity:'medium',advisory:true,title:'A request-controlled URL is accepted without an obvious scheme or host allowlist',ext:['js','mjs','cjs','ts','tsx','php','py','go','java','rb'],pattern:/\bnew\s+URL\s*\(\s*(?:req(?:uest)?\.(?:query|body|params)|request\.(?:args|json|form|query)|userUrl|targetUrl)\b/gi,reason:'Parsing a URL does not make the destination safe. The application still needs rules for schemes, hosts, redirects, and private address ranges when it will connect to the URL.',fix:'Allow only expected schemes and trusted hosts, then validate the final destination before using it for navigation or server-side requests.',confidenceBase:'low'}
  ];
  RULES.push(...EXTRA_RULES);
  // Expanded deterministic corpus. Kept outside the core file so the rule library can grow without making engine logic brittle.
  if (window.OrionPatternPack?.RULES?.length) RULES.push(...window.OrionPatternPack.RULES);

  const RULE_IDS = new Set();
  for (const rule of RULES) {
    if (!rule || !rule.id) throw new Error('ORION rule pack integrity failure: malformed rule entry');
    if (RULE_IDS.has(rule.id)) throw new Error(`ORION rule pack integrity failure: duplicate rule id ${rule.id}`);
    RULE_IDS.add(rule.id);
  }

  const RULE_INDEX = new Map();
  for (const rule of RULES) {
    if (!rule.ext || !rule.ext.length || rule.projectWide) continue;
    for (const ext of rule.ext) {
      if (!RULE_INDEX.has(ext)) RULE_INDEX.set(ext, []);
      RULE_INDEX.get(ext).push(rule);
    }
  }
  const GENERIC_RULES = RULES.filter(rule => !rule.ext || !rule.ext.length || rule.projectWide);
  function rulesForExt(ext) { return [...GENERIC_RULES, ...(RULE_INDEX.get(ext)||[])]; }


  const TAXONOMY = {
    'Access Control': {owasp:'A01:2025 Broken Access Control', cwe:'CWE-862 / CWE-639'},
    'SSRF': {owasp:'A01:2025 Broken Access Control', cwe:'CWE-918'},
    'CSRF': {owasp:'A01:2025 Broken Access Control', cwe:'CWE-352'},
    'CORS': {owasp:'A01:2025 Broken Access Control', cwe:'CWE-942'},
    'Headers': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-693'},
    'Configuration': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-16'},
    'Cookies': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-614 / CWE-1004'},
    'Browser Isolation': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-693'},
    'Transport': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-319'},
    'Supply Chain': {owasp:'A03:2025 Software Supply Chain Failures', cwe:'CWE-1104'},
    'Cryptography': {owasp:'A04:2025 Cryptographic Failures', cwe:'CWE-327'},
    'Secrets': {owasp:'A04:2025 Cryptographic Failures', cwe:'CWE-798'},
    'Injection': {owasp:'A05:2025 Injection', cwe:'CWE-74'},
    'Cross-Site Scripting': {owasp:'A05:2025 Injection', cwe:'CWE-79'},
    'Command Injection': {owasp:'A05:2025 Injection', cwe:'CWE-78'},
    'Path Traversal': {owasp:'A05:2025 Injection', cwe:'CWE-22'},
    'Unvalidated Redirects': {owasp:'A05:2025 Injection', cwe:'CWE-601'},
    'Access Control': {owasp:'A01:2025 Broken Access Control', cwe:'CWE-862'},
    'Authentication': {owasp:'A07:2025 Authentication Failures', cwe:'CWE-287'},
    'Cross-Window Messaging': {owasp:'A05:2025 Injection', cwe:'CWE-79'},
    'Information Exposure': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-200'},
    'Privacy': {owasp:'Outside OWASP Top 10 / privacy readiness', cwe:'Context dependent'},
    'Input Validation': {owasp:'A05:2025 Injection', cwe:'CWE-20'},
    'File Uploads': {owasp:'A05:2025 Injection', cwe:'CWE-434'},
    'Browser Security': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-693'},
    'API Security': {owasp:'A01:2025 Broken Access Control', cwe:'Context dependent'},
    'MIME Security': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-16'},
    'Analysis': {owasp:'Analysis limitation', cwe:'N/A'},
    'XSS': {owasp:'A05:2025 Injection', cwe:'CWE-79'},
    'PROTO': {owasp:'A05:2025 Injection', cwe:'CWE-1321'},
    'INJECT': {owasp:'A05:2025 Injection', cwe:'CWE-74'},
    'SQL': {owasp:'A05:2025 Injection', cwe:'CWE-89'},
    'CMD': {owasp:'A05:2025 Injection', cwe:'CWE-78'},
    'CRYPTO': {owasp:'A04:2025 Cryptographic Failures', cwe:'CWE-327'},
    'HEADERS': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-693'},
    'SUPPLY': {owasp:'A03:2025 Software Supply Chain Failures', cwe:'CWE-1104'},
    'INFRA': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-16'},
    'IAC': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-16'},
    'CI': {owasp:'A03:2025 Software Supply Chain Failures', cwe:'CWE-1104'},
    'API': {owasp:'A01:2025 Broken Access Control', cwe:'CWE-284'},
    'FRAME': {owasp:'A05:2025 Injection', cwe:'CWE-74'},
    'BROWSER': {owasp:'A05:2025 Injection', cwe:'CWE-79'},
    'CONFIG': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-16'},
    'DATA': {owasp:'A01:2025 Broken Access Control', cwe:'CWE-200'},
    'OBS': {owasp:'A09:2025 Security Logging & Alerting Failures', cwe:'CWE-778'},
    'DESER': {owasp:'A08:2025 Software or Data Integrity Failures', cwe:'CWE-502'},
    'XXE': {owasp:'A05:2025 Injection', cwe:'CWE-611'},
    'CACHE': {owasp:'A02:2025 Security Misconfiguration', cwe:'CWE-525'},
    'LOG': {owasp:'A09:2025 Security Logging & Alerting Failures', cwe:'CWE-532'},
    'PRIV': {owasp:'Privacy readiness / context dependent', cwe:'Context dependent'}
  };

  function enrich(f) {
    const meta = TAXONOMY[f.category] || {owasp:'Review manually', cwe:'Context dependent'};
    const k = knowledgeFor(f);
    let out = {...f, owasp:meta.owasp, cwe:meta.cwe, ...buildPlainFinding(f)};
    if (k.advisory || f.advisory) { out.advisory=true; out.affectsScore=false; }
    if (k.confidenceCap) {
      const rank={low:0,medium:1,high:2,critical:3};
      if (rank[out.confidence||'medium'] > rank[k.confidenceCap]) out.confidence=k.confidenceCap;
    }
    return out;
  }


  const PLAIN_FINDINGS = {
    'JS-EVAL-001': ['Your site can turn text into JavaScript code', 'If an attacker can influence that text, they may be able to make the browser run their code.', 'Avoid eval and new Function. Use normal functions and treat incoming values as data.'],
    'JS-TIMEOUT-001': ['A timer is being given text that can be executed as code', 'That makes the timer harder to control safely and can become dangerous if the text is influenced by someone else.', 'Pass a function to the timer instead of a string.'],
    'DOM-XSS-001': ['Website data is being inserted into the page as HTML', 'If that data is ever controlled by a visitor or another service, it could inject unwanted content or scripts.', 'Build the HTML with safe DOM methods or sanitize the value before using it as HTML.'],
    'DOM-XSS-002': ['Data from the browser may be reaching an HTML injection point', 'The value appears to come from a browser-controlled source and then gets written as HTML.', 'Trace the value to the HTML sink and encode, sanitize, or switch to a text-only DOM method.'],
    'DOM-XSS-003': ['The page uses document.write', 'This method can insert markup directly into a live page and is easy to misuse with untrusted data.', 'Replace it with normal DOM methods or your framework’s rendering APIs.'],
    'DOM-XSS-004': ['React is being told to render raw HTML', 'React normally escapes text for you. This escape hatch turns that protection off for the value being rendered.', 'Use normal React rendering, or sanitize the HTML with a maintained allowlist before rendering it.'],
    'DOM-XSS-005': ['Vue is being told to render raw HTML', 'Vue normally escapes text. Raw HTML can become active content when the value is not fully trusted.', 'Use normal Vue interpolation, or sanitize the value before rendering raw HTML.'],
    'DOM-XSS-006': ['Svelte is being told to render raw HTML', 'Svelte normally treats content as text. Raw HTML can become active page content when the value is not trusted.', 'Use normal text rendering, or sanitize the HTML with a maintained allowlist before rendering it.'],

    'WEB-REDIRECT-001': ['A visitor may be able to control where the site redirects them', 'An attacker could create a link that sends people through your site to a destination you did not intend.', 'Only allow known internal paths or a small list of trusted domains.'],
    'WEB-REDIRECT-002': ['The site redirects users using a value that may change', 'Dynamic redirects are worth checking because the destination may come from user input or external data.', 'Make sure the destination is limited to trusted paths or domains.'],
    'SECRETS-001': ['A password, private key, or other secret may be inside the code', 'Anyone who gets the code could potentially get that secret too.', 'Remove real secrets from the project, rotate exposed credentials, and load them only on the server.'],
    'SECRETS-002': ['A recognizable service credential may be inside the code', 'Provider keys can be abused if they leak through source control or browser code.', 'Treat it as exposed, rotate it if real, and move the secret behind a server-side boundary.'],
    'AUTH-001': ['A login token is stored in browser storage', 'JavaScript running on the page can read browser storage, so a script injection could steal the token.', 'Prefer secure, appropriately scoped cookies for session material when your architecture supports them.'],
    'AUTH-002': ['A token is being decoded without clear proof that it is verified', 'Reading a token is not the same as checking that it was signed by the right system and is still valid.', 'Verify the signature and important claims on a trusted server.'],
    'AUTH-003': ['A password or secret may be written to logs', 'Logs are often copied, stored, and shared. Sensitive values can escape far beyond the original app.', 'Remove secret values from logs and log only safe identifiers.'],
    'COOKIE-001': ['A login cookie may be missing important safety settings', 'Without the right cookie flags, a session can be easier to steal or misuse.', 'Set Secure, HttpOnly, and an appropriate SameSite value where they fit your login flow.'],
    'COOKIE-002': ['A cross-site cookie is missing the Secure flag', 'Browsers require Secure for SameSite=None cookies, and the combination is usually only needed for deliberate cross-site flows.', 'Use SameSite=Lax or Strict where possible; otherwise add Secure.'],
    'CORS-001': ['Your server may trust every website while also allowing logged-in requests', 'That can let an untrusted website ask for data as the user.', 'Replace the wildcard origin with a small trusted allowlist.'],
    'CORS-002': ['Your server may be echoing back any website as trusted', 'An attacker-controlled website could become an allowed origin if the request value is reflected without checking it.', 'Compare the origin to a trusted allowlist before returning it.'],
    'INJECT-SQL-001': ['User data may be getting inserted directly into an SQL query', 'An attacker could change the query instead of being treated as ordinary data.', 'Use parameterized queries or a trusted query builder.'],
    'INJECT-SQL-002': ['Request data may be reaching a raw SQL command', 'Values from a request should not be allowed to change the meaning of the SQL statement.', 'Bind user input as parameters instead of joining it into SQL.'],
    'INJECT-CMD-001': ['User-controlled data may be reaching an operating-system command', 'That can let an attacker run commands on the machine running your website.', 'Avoid shell commands where possible. Otherwise use fixed commands and pass arguments through safe APIs.'],
    'PATH-001': ['A file path may be built from user-controlled input', 'A crafted path can sometimes make the server read, overwrite, or create files outside the intended folder.', 'Keep paths server-generated and reject traversal such as .. before touching the filesystem.'],
    'UPLOAD-001': ['The upload system does not clearly limit what files it accepts', 'A visitor may be able to upload a dangerous file or trigger unexpected processing.', 'Limit file size and type, generate the stored filename on the server, and keep uploads out of executable folders.'],
    'PATH-002': ['The uploaded filename is still being reused for storage', 'Even a partly cleaned filename can create confusing paths, collisions, or unsafe assumptions later.', 'Generate a random server-side filename and store the original name only as display metadata.'],
    'CSRF-001': ['A logged-in action may not have a clear cross-site request check', 'Another website could try to make a user perform an action while they are still signed in.', 'Use SameSite cookies and, where needed, a CSRF token plus Origin or Referer checks.'],
    'HEADERS-001': ['The site does not clearly set a Content Security Policy', 'A strong browser policy can limit what scripts and other resources an injected page is allowed to run.', 'Add a CSP that matches the resources your site actually needs.'],
    'HEADERS-002': ['The site does not clearly control referrer information', 'A browser may send more of the current URL to another website than you intended.', 'Set a deliberate Referrer-Policy such as strict-origin-when-cross-origin when it fits.'],
    'HEADERS-003': ['The site does not clearly stop other sites from framing it', 'Framing can be used in deceptive interfaces and clickjacking attacks.', 'Add frame-ancestors in CSP or X-Frame-Options if the site should not be embedded.'],
    'HEADER-CTO-001': ['The site does not clearly disable MIME sniffing', 'Browsers can sometimes guess a different file type than the server intended.', 'Set X-Content-Type-Options: nosniff at the server or edge.'],
    'HTTP-001': ['The site loads something over plain HTTP', 'Unencrypted traffic can be changed or observed while it travels between the visitor and the server.', 'Use HTTPS for all site resources and API calls.'],
    'HTTP-002': ['A secure page appears to load an insecure resource', 'One insecure script, image, or connection can weaken an otherwise secure page.', 'Change the resource URL to HTTPS or remove it.'],
    'DEBUG-001': ['Debug mode appears to be left on', 'Debug output can reveal internal details that help attackers understand the app.', 'Disable debug mode in production.'],
    'ERROR-001': ['The app may expose detailed error messages', 'Stack traces and internal errors can reveal file paths, libraries, queries, or other clues.', 'Show a generic error to visitors and keep details in protected server logs.'],
    'DEPEND-001': ['A dependency may have a known security concern', 'Third-party code becomes part of your attack surface too.', 'Check the package version and update to a maintained safe version.'],
    'DEPEND-002': ['A package is being loaded from an unsafe or unpinned source', 'Builds can change unexpectedly, and a compromised dependency can affect the whole site.', 'Pin trusted versions and use a lockfile or trusted package source.'],
    'HTML-001': ['A link opens a new tab without an obvious safety guard', 'The new page may be able to interact with the original page in older or unusual browser situations.', 'Add rel="noopener noreferrer" where appropriate.'],
    'HTML-002': ['An HTML form may submit to an unexpected destination', 'Sensitive form data could be sent somewhere you did not intend.', 'Use explicit same-origin or trusted destinations and review every form action.'],
    'HTML-003': ['A link opens a new tab without explicitly adding a safety attribute.', 'Modern browsers already protect many new-tab links, so this is usually a hardening check rather than a confirmed vulnerability.', 'Add rel="noopener" for compatibility and explicit intent, or remove target="_blank" when it is not needed.'],
    'CRYPTO-001': ['Weak or outdated encryption is being used', 'Old algorithms can be much easier to break with modern tools.', 'Use a modern, well-maintained cryptographic primitive and follow the library’s recommended settings.'],
    'CRYPTO-002': ['Encryption settings may not be strong enough', 'Even good algorithms become unsafe when used with weak settings or predictable values.', 'Use the library’s secure defaults and a vetted construction.'],
    'AUTH-004': ['The app may accept a login or identity check that is too easy to fake', 'Weak identity checks can let someone act as another user.', 'Verify identity on the server and reject client-only authentication claims.'],
    'ACCESS-001': ['The app may let users access records they do not own', 'Changing an ID in a request should never be enough to see or change somebody else’s data.', 'Check ownership or role permissions on the server for every sensitive resource.'],
    'ACCESS-002': ['A sensitive action may rely too much on the browser', 'A user can change browser requests, so important permissions cannot live only in frontend code.', 'Repeat authorization checks on the server for every protected action.'],
    'SSRF-001': ['The server may fetch a URL chosen by the user', 'Attackers can abuse server-side requests to reach internal services that visitors cannot normally access.', 'Allow only expected destinations and block private/internal network ranges.'],
    'TEMPLATE-001': ['User input may be reaching a template engine unsafely', 'Template syntax can sometimes become code instead of plain text.', 'Pass user values as data and use the template engine’s safe escaping features.'],
    'LOG-001': ['Sensitive information may be written to logs', 'Logs can be copied or retained, so secret data can leak long after a request finishes.', 'Remove passwords, tokens, keys, and personal data from logs.'],
    'CONFIG-001': ['A production setting may be unsafe', 'Configuration can quietly weaken security even when the application code looks fine.', 'Review the flagged setting and use the framework’s secure production default.'],
    'CONFIG-002': ['An important security setting is not clearly defined', 'Leaving security behavior to defaults can produce surprises after a dependency or deployment change.', 'Set the intended value explicitly in production configuration.'],
    'DEPEND-003': ['A dependency install step can run arbitrary code', 'Install scripts execute with build permissions and can become a supply-chain risk.', 'Only use trusted packages and review install hooks before accepting them.'],
    'DEPEND-004': ['A third-party script is loaded without a fixed integrity check.', 'The remote file can change outside your deployment process, so a compromised provider could change what your page runs.', 'Pin the exact resource when practical and use Subresource Integrity when the resource supports it.'],
    'PRIV-001': ['The site appears to collect personal data without a clear notice', 'Visitors may need to understand what information is collected and why.', 'Review the site’s privacy notice and make the data collection explanation clear.'],
    'PRIV-002': ['The site may set tracking or non-essential cookies without a clear choice', 'Visitors may be tracked before they understand what is happening or have made a choice.', 'Review cookie consent and only activate non-essential tracking when your legal requirements and consent flow allow it.'],
    'PRIV-003': ['The site sends personal or tracking data to a third party', 'Information shared with another service can become a separate privacy and security responsibility.', 'List the third party, minimize the data sent, and review the legal basis and vendor settings.'],
    'AUTH-005': ['A login flow may be missing a clear security control', 'Authentication needs several small protections working together to resist guessing, replay, and session theft.', 'Review login, session expiry, password handling, and brute-force protection together.'],
    'POSTMSG-001': ['A window message is accepted without clearly checking who sent it', 'Another website may be able to send the same message and trigger the action.', 'Check event.origin against an exact trusted origin before acting on the message.'],
    'POSTMSG-002': ['A window message may expose more data than necessary', 'A trusted message channel can still leak information if the response is too broad.', 'Send only the minimum data the receiving page needs.'],
    'POSTMSG-003': ['Cross-window messages are handled without strong validation', 'Unexpected messages can trigger actions or corrupt application state.', 'Validate origin, message shape, and allowed actions before handling the message.'],
    'RANDOM-001': ['Random values may not be strong enough for security use', 'Predictable random values can make tokens, reset links, or other secrets guessable.', 'Use the platform’s cryptographically secure random generator.'],
    'PROTO-001': ['Object data may be able to change built-in JavaScript behavior', 'Prototype pollution can alter how unrelated parts of an application behave.', 'Validate object keys and avoid merging untrusted objects into trusted prototypes or configuration.'],
    'NOSQL-001': ['User input may directly shape a NoSQL query', 'An attacker can sometimes change the meaning of the query instead of supplying a normal value.', 'Allow only expected fields and use the database driver’s safe query patterns.'],
    'NOSQL-002': ['NoSQL filtering may accept raw request objects', 'Unexpected operators can sneak into a query when request objects are trusted too much.', 'Pick allowed fields explicitly and reject database operators from user input.'],
    'IFRAME-001': ['The site embeds another page without a clear trust boundary', 'Embedded content can become a path for unexpected interaction or data sharing.', 'Only embed trusted origins and use sandbox/permissions deliberately.'],
    'IFRAME-002': ['An iframe may have broader permissions than needed', 'Extra browser permissions give embedded content more power than necessary.', 'Use the narrowest sandbox and allowlist you need.'],
    'SOURCE-MAP-001': ['A production source map is exposed', 'It can reveal the original source structure and internal names to anyone visiting the site.', 'Disable public source maps in production or restrict access when they are needed for debugging.'],
    'ENV-PUBLIC-001': ['A configuration value may be exposed to the browser', 'Values shipped to the browser should be treated as public.', 'Keep real secrets on the server and only expose values that are safe to publish.'],
    'APIKEY-001': ['An API key appears in browser-delivered code', 'Visitors can see and reuse keys that are shipped to the browser.', 'Move the key to a server-side integration or replace it with a public, restricted key designed for browsers.'],
    'DEBUG-ENDPOINT-001': ['A debug or internal endpoint appears reachable', 'Internal endpoints can expose tools or information that attackers should not have.', 'Remove it from production or protect it with strong server-side access control.'],
    'GRAPHQL-001': ['A GraphQL endpoint may allow overly broad queries', 'Attackers can sometimes request far more data than a normal user needs.', 'Limit exposed fields and require authorization on sensitive data.'],
    'CORS-003': ['Cross-origin access rules may be broader than necessary', 'A broad trust rule can let unrelated websites interact with your API.', 'Keep the allowed origins and methods as small as the application needs.'],
    'HEADER-PROBE-001': ['A server response may reveal what software is running', 'Version details can give attackers useful clues about known weaknesses.', 'Remove unnecessary product and version headers from production responses.'],
    'HTML-DATA-001': ['Page data is exposed in a place the browser can read directly', 'Anything sent to the browser should be treated as public, even if the HTML is meant to hide it.', 'Do not put secrets or private data into client-visible HTML.'],
    'SECRET-URL-001': ['A secret appears to be included in a URL', 'URLs can end up in browser history, logs, analytics, and referrer data.', 'Move the secret into a secure header or cookie and rotate it if it was real.'],
    'AUTH-006': ['A session ID is being put into a URL', 'URLs are copied, logged, saved in browser history, and sometimes sent to other services, so the session can leak.', 'Use secure cookies or an authorization header instead of putting the session ID in the URL.'],
    'CSS-001': ['A style value may be built from untrusted input', 'Unexpected CSS or URL values can sometimes change what the browser loads or displays.', 'Allowlist expected values and do not insert arbitrary user data into style or URL properties.'],
    'HTML-004': ['A dangerous browser feature is enabled from markup', 'Some HTML attributes can give embedded content more power than intended.', 'Use the narrowest permissions and sandbox settings you need.'],
    'JS-PROTO-001': ['JavaScript object properties are assigned from untrusted keys', 'Special object keys can change application behavior in surprising ways.', 'Allowlist property names before assigning them.'],
    'JS-FETCH-CREDENTIALS-001': ['Browser requests may send login credentials across origins', 'Sending credentials to another origin increases the damage if that origin is not fully trusted.', 'Keep credentialed requests same-origin where possible and explicitly verify trusted origins.'],
    'AUTH-007': ['A security-sensitive action is missing a clear server-side check', 'A browser can be modified by the user, so client-side checks alone do not protect important actions.', 'Enforce the permission again on the server.'],
    'ERROR-002': ['An error response may reveal internal server details', 'Detailed errors can show attackers how your app is built and where it failed.', 'Return a generic message to users and keep the technical details in protected logs.'],
    'LOG-002': ['Request data may be copied into logs without filtering', 'Attackers can sometimes inject misleading or sensitive values into logs.', 'Use structured logging and sanitize or limit untrusted values.'],
    'FRAMEWORK-XSS-001': ['A framework escape hatch may render raw HTML', 'Raw HTML bypasses the framework’s normal escaping and can become script injection.', 'Use the framework’s normal rendering and sanitize only when raw HTML is truly required.'],
    'FRAMEWORK-XSS-002': ['A framework template may allow raw HTML content', 'Raw markup can become executable content when the value is not trusted.', 'Keep the value escaped or sanitize it with a maintained allowlist.'],
    'FRAMEWORK-XSS-003': ['A framework directive may insert HTML without escaping', 'This can turn user or remote data into active page content.', 'Use the safe text rendering path or sanitize the value first.'],
    'FRAMEWORK-XSS-004': ['A component may render browser-controlled data as HTML', 'Values from URLs or storage should not automatically become HTML.', 'Treat the value as text unless you have a strong reason to render sanitized HTML.'],
    'SECURITY-JWT-001': ['A JWT may be accepted without a strong signature check', 'A fake or modified token should never be enough to become another user.', 'Verify the signature, algorithm, issuer, audience, and expiry on the server.'],
    'SECURITY-JWT-002': ['A JWT may trust claims supplied by the client', 'A user can modify the browser request, so client claims cannot be treated as proof of permission.', 'Re-check sensitive claims and permissions on the server.'],
    'BROWSER-DOM-001': ['Browser-controlled data is used in a sensitive DOM operation', 'Values coming from the URL, storage, or messages can be changed by attackers.', 'Validate and safely render browser-controlled values.'],
    'DOM-URL-001': ['A URL value is inserted into the page without a strong check', 'Unexpected URLs can lead to phishing, unwanted navigation, or unsafe resource loading.', 'Allow only expected URL schemes and trusted origins.'],
    'RUNTIME-001': ['A runtime setting may expose the app to unsafe behavior', 'Production runtime flags can quietly weaken security.', 'Review the flagged runtime setting and use the secure production value.'],
    'RUNTIME-002': ['A runtime feature is enabled without a clear security boundary', 'Powerful features should be restricted to the exact places that need them.', 'Turn it off unless required and add server-side authorization where applicable.'],
    'API-INPUT-001': ['An API input is accepted without a clear type or size check', 'Attackers can send unexpected values, oversized payloads, or data your code was not designed to handle.', 'Validate the type, format, range, and size of every important input.'],
    'API-INPUT-002': ['An API accepts more fields than the code clearly needs', 'Extra fields can let attackers change values you never meant the client to control.', 'Allowlist accepted fields and ignore or reject everything else.'],
    'SECRET-HTML-001': ['Sensitive data may be embedded directly into a public page', 'Anything the browser receives can be inspected by the person visiting the site.', 'Keep secrets on the server and only send data the browser genuinely needs.'],
    'SOURCE-DEBUG-001': ['Debug information is included in the shipped source', 'It can reveal internal details and make the application easier to reverse-engineer.', 'Remove debug output and development-only helpers from production builds.'],
    'HEADER-COOP-001': ['The app may need stronger separation between browser windows', 'Some powerful browser capabilities work best when your pages are isolated from other origins.', 'Review COOP together with COEP and CORP before enabling it.'],
    'HEADER-COEP-001': ['The app may need tighter control over cross-origin resources', 'Some browser features require embedded resources to opt in deliberately.', 'Review COEP together with COOP, CORP, and your external resources before enabling it.'],
    'DESER-001': ['The server may be rebuilding objects from untrusted serialized data', 'Some serialization formats can execute or instantiate more than simple data.', 'Only deserialize trusted data and use safe data-only formats where possible.'],
    'DESER-002': ['Untrusted data may be passed into a powerful deserializer', 'A malicious payload can sometimes trigger unexpected code or object creation.', 'Use a safe parser with an allowlist of expected types and fields.'],
    'XXE-001': ['XML input may be allowed to read external resources', 'A crafted XML document can sometimes make the server access local files or internal services.', 'Disable external entities and use a parser configured for untrusted XML.'],
    'TLS-VERIFY-001': ['TLS certificate verification appears to be disabled', 'The app could accept a fake server and send data to an attacker.', 'Turn certificate verification back on in production.'],
    'CRYPTO-HASH-001': ['A weak hash may be used for passwords or security tokens', 'Fast or outdated hashes are easier to crack or misuse.', 'Use a password hashing function such as Argon2id, scrypt, or bcrypt for passwords; use modern hashes for integrity where appropriate.'],
    'CRYPTO-KEY-001': ['A fixed encryption key appears to be embedded in the app', 'Anyone who gets the app code can recover a key that was meant to stay secret.', 'Generate and store keys securely on the server or in a secrets manager.'],
    'CRYPTO-IV-001': ['An encryption value is reused when it should be fresh', 'Reusing a nonce or IV can reveal information and weaken encryption badly.', 'Generate a fresh cryptographically secure nonce/IV for each encryption operation when the algorithm requires it.'],
    'CMD-SHELL-001': ['The app may pass input into a shell command', 'A crafted value can potentially escape the intended command and run other commands.', 'Avoid shells; use direct process APIs with fixed executables and validated arguments.'],
    'FS-PERM-001': ['A file or folder may be writable by more users than necessary', 'Extra write access can let an attacker replace files or inject code.', 'Use the smallest filesystem permissions the application needs.'],
    'REGEX-DOS-001': ['A regular expression may take a very long time on crafted input', 'An attacker could send input that keeps the server busy and makes the site slow or unavailable.', 'Use a simpler regex, bound input length, or use a safe regex engine.'],
    'AUTH-RATE-001': ['There is no clear limit on repeated login attempts', 'Attackers can make many guesses against a password or code.', 'Add rate limiting, sensible lockouts or delays, and monitoring to authentication endpoints.'],
    'GRAPHQL-DEPTH-001': ['GraphQL queries may be allowed to become too deep or expensive', 'A single request could consume a large amount of server work and slow down the site.', 'Limit query depth or cost and apply sensible request limits.'],
    'PROJECT-PRIV-001': ['The site does not clearly show the privacy or legal notices it may need', 'People may need a clear explanation of what data the site collects and how it is used.', 'Review your privacy, cookie, and terms pages based on where you operate and what data you collect. This is a readiness check, not legal advice.'],
    'PROJECT-DEP-001': ['The project has packages but no clear lockfile', 'The exact dependency versions can change between installs, making builds less predictable.', 'Commit the package manager lockfile and review updates deliberately.'],
    'PROJECT-COOP-001': ['The project may need stronger browser isolation', 'Some advanced browser features need deliberate cross-origin isolation.', 'Review COOP, COEP, and CORP together only if the application actually needs those features.'],
    'FILE-001': ['Part of a very large source file was skipped', 'Orion capped this file to keep the browser responsive, so issues in the skipped section may not have been seen.', 'Review the skipped section separately or scan a smaller project.']
  };

  const PLAIN_CATEGORY = {
    'Injection': 'The app may be letting input change what the computer executes.',
    'Cross-Site Scripting': 'Website data may be turning into active browser content.',
    'Unvalidated Redirects': 'A link or redirect may send visitors somewhere the site owner did not intend.',
    'Secrets': 'A private key, token, or credential may be exposed in the project.',
    'Authentication': 'The way the app proves who a user is may be easier to abuse than it should be.',
    'Cookies': 'A login cookie may not be protected as strongly as it could be.',
    'CORS': 'The app may trust other websites more broadly than necessary.',
    'Command Injection': 'User input may be able to influence commands run by the server.',
    'File Uploads': 'Visitors may be able to upload files that the server did not intend to accept.',
    'CSRF': 'Another website may be able to make a signed-in user trigger an action.',
    'Headers': 'The browser is missing a security rule that can reduce attack impact.',
    'MIME Security': 'The browser is not being told to stick to the file types the server declares.',
    'Browser Isolation': 'Cross-origin browser separation may need a closer look.',
    'Supply Chain': 'Third-party packages can change what code runs in your project.',
    'Privacy': 'The site may need clearer explanations or choices around personal data and tracking.',
    'Input Validation': 'The app may accept values without checking that they are the shape it expects.',
    'API Security': 'An API action may not be checking permissions or inputs strongly enough.',
    'Analysis': 'Orion could not fully inspect this part of the project.',
    'XSS': 'Website data may be turning into active browser content.',
    'PROTO': 'Untrusted object data may be changing how JavaScript objects behave.',
    'INJECT': 'Input may be changing the meaning of a query, template, or interpreter.',
    'SQL': 'Input may be changing a database query instead of staying ordinary data.',
    'CMD': 'Input may be influencing an operating-system command.',
    'CRYPTO': 'A cryptographic setting or secret deserves a closer security check.',
    'HEADERS': 'A browser or server security policy may be weaker than intended.',
    'SUPPLY': 'Build dependencies or installation steps may be changing outside normal review.',
    'INFRA': 'The deployment configuration may grant more access than the workload needs.',
    'IAC': 'Infrastructure rules may expose services or grant broader permissions than required.',
    'CI': 'Build automation may be executing or exposing more than intended.',
    'API': 'An API boundary may accept more data, access, or work than intended.',
    'FRAME': 'A framework-specific trust or rendering boundary needs a closer look.',
    'BROWSER': 'A browser capability or data flow may cross a trust boundary.',
    'CONFIG': 'A framework or deployment setting may weaken the security boundary.',
    'DATA': 'The API or application may expose more internal data than intended.',
    'OBS': 'Logs or telemetry may contain information that should stay protected.',
    'DESER': 'Serialized data may cross a trust boundary in a risky format.',
    'XXE': 'XML parsing settings may expose external resources to untrusted documents.',
    'CACHE': 'Caching behavior may cross user or trust boundaries.',
    'LOG': 'Application logs may capture credentials or private request data.',
    'PRIV': 'Telemetry or stored data may include more personal information than necessary.'
  };

  function knowledgeFor(f) {
    return (KNOWLEDGE.rules && KNOWLEDGE.rules[f.id]) || (KNOWLEDGE.categories && KNOWLEDGE.categories[f.category]) || {};
  }

  function buildPlainFinding(f) {
    const k = knowledgeFor(f);
    const known = PLAIN_FINDINGS[f.id];
    if (k.plainTitle || k.plainWhy || k.repair || k.verify) {
      return {
        plainTitle: k.plainTitle || known?.[0] || f.title,
        plainWhy: k.plainWhy || known?.[1] || f.reason || KNOWLEDGE.categories?.[f.category]?.intent || 'This pattern deserves a closer security check.',
        plainFix: k.repair || known?.[2] || f.fix || 'Review the flagged area and make the smallest safe change that removes the risk.',
        verify: k.verify || KNOWLEDGE.categories?.[f.category]?.verify || 'Re-check the affected behavior after the change.'
      };
    }
    if (known) return {plainTitle:known[0], plainWhy:known[1], plainFix:known[2], verify:'Re-check the affected behavior after the change.'};
    const title = String(f.title||'Security issue');
    const words = title
      .replace(/\bpotentially missing\b/ig,'may be missing')
      .replace(/\bdetected\b/ig,'found')
      .replace(/\bappears to\b/ig,'may')
      .replace(/\bobvious\b/ig,'clear')
      .replace(/\bunvalidated\b/ig,'not checked')
      .replace(/\bunsafe\b/ig,'risky')
      .replace(/\bsink\b/ig,'sensitive browser operation')
      .replace(/\bsource-to-sink flow\b/ig,'input may reach a risky browser operation')
      .replace(/\bcredentials\b/ig,'login details')
      .replace(/\brequest-derived\b/ig,'request data')
      .replace(/\bserver-side\b/ig,'server')
      .replace(/\bMIME-sniffing\b/ig,'file-type guessing')
      .replace(/\bcross-origin\b/ig,'between websites')
      .replace(/\bserialization\b/ig,'saved data format')
      .replace(/\bprototype pollution\b/ig,'unexpected changes to shared JavaScript objects');
    return {
      plainTitle: words,
      plainWhy: PLAIN_CATEGORY[f.category] || f.reason || 'This pattern deserves a security review.',
      plainFix: f.fix || 'Review the flagged code and make the smallest safe change that removes the risk.',
      verify: KNOWLEDGE.categories?.[f.category]?.verify || 'Re-check the affected behavior after the change.'
    };
  }


  const severityWeight = {critical: 18, high: 9, medium: 4, low: 1};

  function extOf(path) { const lower=path.toLowerCase(); if(lower==='dockerfile' || lower.endsWith('/dockerfile')) return 'dockerfile'; if(lower==='makefile' || lower.endsWith('/makefile')) return 'makefile'; const m=lower.match(/\.([a-z0-9]+)$/); return m ? m[1] : ''; }
  function isTextFile(file) { const ext = extOf(file.name || file.path || ''); return TEXT_EXT.has(ext) && !SKIP_EXT.has(ext); }
  function normalizeText(s) { return s.replace(/\r\n/g,'\n').replace(/\r/g,'\n'); }
  function lineAt(text, idx) { return text.slice(0, idx).split('\n').length; }
  function getLineSnippet(text, idx) { const lines = text.split('\n'); const line = Math.max(1, lineAt(text, idx)); const start = Math.max(0,line-2); const end = Math.min(lines.length,line+1); return {line, snippet: lines.slice(start,end).map((x,i)=>`${start+i+1} | ${x}`).join('\n')}; }
  function allMatches(re, text, limit=20) {
    if (!(re instanceof RegExp)) return [];
    const out=[]; re.lastIndex=0; let m;
    while ((m=re.exec(text)) && out.length<limit) {
      out.push({index:m.index, match:m[0]});
      if (re.lastIndex===m.index) re.lastIndex++;
    }
    re.lastIndex=0;
    return out;
  }

  function matchesRule(rule, text, ext, lowerText) {
    if (rule.projectWide) return [];
    if (rule.needle && lowerText && !lowerText.includes(String(rule.needle))) return [];
    if (rule.ext && !rule.ext.includes(ext)) return [];
    const hits=[];
    if (typeof rule.check === 'function') return rule.check(text, ext) || [];
    if (rule.absence) {
      const anchored = rule.absence.anchor.test(text);
      const missing = !rule.absence.absent.test(text);
      rule.absence.anchor.lastIndex=0; rule.absence.absent.lastIndex=0;
      if (anchored && missing) hits.push({index: Math.max(0,text.search(rule.absence.anchor))});
      return hits;
    }
    if (rule.flow) {
      const sources = rule.flow.sources.flatMap(re=>allMatches(re,text,12));
      const sinks = rule.flow.sinks.flatMap(re=>allMatches(re,text,12));
      const maxDistance = rule.flow.maxDistance || 900;
      let best=null;
      for (const s of sources) {
        for (const k of sinks) {
          const forward = k.index >= s.index && k.index-s.index <= maxDistance;
          const reverse = rule.flow.allowReverse && k.index < s.index && s.index-k.index <= maxDistance && lineAt(text,k.index) === lineAt(text,s.index);
          if (!forward && !reverse) continue;
          const between = text.slice(Math.min(s.index,k.index), Math.min(text.length,Math.max(s.index,k.index)+Math.max(s.match.length,k.match.length)+80));
          if (rule.guard && rule.guard.test(between)) continue;
          if (!best || (k.index-s.index) < (best.sink.index-best.source.index)) best={source:s,sink:k};
        }
      }
      if (best) hits.push({index:best.sink.index, sourceIndex:best.source.index});
      return hits;
    }
    if (!rule.pattern) return hits;
    const matches = allMatches(rule.pattern,text,8);
    for (const m of matches) {
      const windowStart=Math.max(0,m.index-260), windowEnd=Math.min(text.length,m.index+m.match.length+260);
      const context=text.slice(windowStart,windowEnd);
      if (!rule.guard || !rule.guard.test(context)) hits.push(m);
    }
    return hits;
  }


  function normalizeProjectPath(raw) {
    return String(raw || '').replace(/\\/g,'/').replace(/^\.\//,'').replace(/^\/+/, '').split('/').filter(part=>part && part !== '.').join('/');
  }

  function canonicalizeFiles(files) {
    const normalized = files.map(f => ({...f, path: normalizeProjectPath(f.path || f.name || '')}))
      .filter(f => f.path && !f.path.split('/').some(part => part === '..'));
    const byPath = new Map();
    for (const f of normalized) {
      const existing = byPath.get(f.path);
      if (!existing) byPath.set(f.path, f);
      else if ((existing.text || '').length < (f.text || '').length) byPath.set(f.path, f);
    }
    let unique = [...byPath.values()];
    if (!unique.length) return [];

    // Collapse archives that accidentally contain both `file` and `Project/file`.
    // We only remove the prefixed copy when the unprefixed file exists with matching content.
    const roots = [...new Set(unique.map(f => f.path.split('/')[0]).filter(Boolean))];
    for (const root of roots) {
      const prefixed = unique.filter(f => f.path.startsWith(root + '/'));
      if (!prefixed.length) continue;
      let mirrored = 0;
      const mirroredPaths = new Set();
      for (const f of prefixed) {
        const stripped = f.path.slice(root.length + 1);
        const twin = byPath.get(stripped);
        if (twin && twin !== f && (twin.text || '') === (f.text || '') && (twin.size == null || f.size == null || twin.size === f.size)) {
          mirrored++; mirroredPaths.add(f.path);
        }
      }
      if (mirrored >= 2 && mirrored / prefixed.length >= 0.6) {
        unique = unique.filter(f => !mirroredPaths.has(f.path));
      }
    }

    const parts = unique.map(f => f.path.split('/'));
    const first = parts[0][0];
    const genericRoot = /^(src|public|assets|static|app|lib|pages|components|dist|build)$/i.test(first || '');
    const hasProjectMarker = unique.some(f => /(^|\/)(package\.json|requirements\.txt|pyproject\.toml|cargo\.toml|go\.mod|composer\.json|readme\.md|server\.(?:py|js|ts)|main\.(?:py|js|ts)|index\.html)$/i.test(f.path));
    const singleRoot = first && !genericRoot && unique.every(f => { const p=f.path.split('/'); return p.length > 1 && p[0] === first; });
    if (singleRoot && hasProjectMarker) {
      return unique.map(f => ({...f, path:f.path.split('/').slice(1).join('/')}));
    }
    return unique;
  }

  function projectProfile(files) {
    const names = files.map(f=>f.path.toLowerCase());
    return {
      hasPackage: names.some(n => /(^|\/)package\.json$/.test(n)),
      hasLock: names.some(n => /(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb)$/.test(n)),
      hasServer: names.some(n => /(?:server|api|backend|functions|lambda|worker|route|controller)/.test(n)),
      hasAuth: names.some(n => /(?:auth|login|signup|session|oauth|jwt|password)/.test(n)) || files.some(f => /\b(?:Set-Cookie|session(?:_?id)?|cookie|login|sign(?:-?in|up)|oauth|jwt|password)\b/i.test(f.text || '')),
      hasHtml: names.some(n => /\.(?:html|htm)$/.test(n)),
      hasPrivacy: names.some(n => /(?:privacy|cookie|terms)/.test(n)) || files.some(f => /<(?:a|footer|nav)[^>]+(?:privacy|cookie|terms)[^>]*>|>\s*(?:privacy policy|cookie policy|terms(?: of service)?)\s*</i.test(f.text || '')),
      sourceCount: files.length
    };
  }

  function addProjectSignals(findings, files, profile) {
    const htmlFiles = files.filter(f=>/(?:\.html?|\.php)$/i.test(f.path));
    if (htmlFiles.length && !profile.hasPrivacy) {
      findings.push(enrich({id:'PROJECT-PRIV-001',category:'Privacy',severity:'low',advisory:true,title:'No obvious privacy/terms document detected',file:htmlFiles[0].path,line:1,evidence:'No filename or linked content matched common privacy/cookie/terms markers.',reason:'Public sites that collect personal data may need transparent notices and policy links depending on jurisdiction.',fix:'Review whether your site needs privacy, cookie, terms, or consent disclosures. This is a readiness check, not legal advice.',confidence:'low',detectedBy:'project-signal',affectsScore:false}));
    }
    if (profile.hasPackage && !profile.hasLock) {
      const pkg = files.find(f=>/package\.json$/.test(f.path.toLowerCase()));
      findings.push(enrich({id:'PROJECT-DEP-001',category:'Supply Chain',severity:'low',advisory:true,title:'Package manifest found without an obvious lockfile',file:pkg?.path || 'package.json',line:1,evidence:'package.json detected; no package-lock.json, pnpm-lock.yaml, yarn.lock, or bun.lockb detected.',reason:'Unpinned dependency resolution can create build-to-build drift.',fix:'Commit the package manager lockfile and review dependency updates deliberately.',confidence:'high',detectedBy:'project-signal'}));
    }

    const htmlEntry = files.find(f=>/(^|\/)index\.(?:html|htm)$/.test(f.path.toLowerCase())) || htmlFiles[0];
    if (htmlEntry) {
      const combined = files.map(f=>f.text||'').join('\n');
      const headerChecks = [
        ['HEADERS-001','Headers','low','Deployment does not show a Content Security Policy in source',/Content-Security-Policy/i,'A strong CSP can reduce the impact of certain script injection classes.','Add a deliberate CSP at the deployment/edge layer tailored to the site\'s actual script, style, image, font, connect, and frame requirements.'],
        ['HEADERS-002','Headers','low','Deployment does not show a Referrer-Policy in source',/(?:Referrer-Policy|<meta[^>]+name=[\"']referrer)/i,'A restrictive Referrer-Policy can reduce unintended URL leakage to third parties.','Set a deliberate Referrer-Policy, commonly strict-origin-when-cross-origin or stricter depending on requirements.'],
        ['HEADERS-003','Headers','low','Deployment does not show frame-embedding protection in source',/(?:frame-ancestors|X-Frame-Options)/i,'Without frame-embedding controls, sensitive pages may be framed by other origins.','Use CSP frame-ancestors and/or X-Frame-Options according to the app\'s embedding requirements.'],
        ['HEADER-CTO-001','MIME Security','low','Deployment does not show MIME-sniffing protection in source',/X-Content-Type-Options/i,'X-Content-Type-Options: nosniff can prevent certain MIME confusion attacks.','Set X-Content-Type-Options: nosniff at the server/edge layer.']
      ];
      for (const [id,category,severity,title,rx,reason,fix] of headerChecks) {
        if (!rx.test(combined)) findings.push(enrich({id,category,severity,title,file:'deployment / response headers',line:1,evidence:`Orion could not find a source/config signal for ${id}. This is a deployment review item because HTTP response headers may be configured outside the uploaded files.`,reason,fix,confidence:'low',detectedBy:'project-signal',advisory:true,affectsScore:false}));
      }
    }

    const serverText = files.filter(f=>/(?:server|api|backend|route|controller|worker|lambda)/i.test(f.path)).map(f=>f.text||'').join('\n');
    const hasStateChange = /\b(?:do_POST|do_PUT|do_PATCH|do_DELETE)\b|\.(?:post|put|patch|delete)\s*\(/i.test(serverText);
    const hasCookieSession = /\b(?:Set-Cookie|req\.cookies|request\.cookies|session|session_id|cookie-parser|express-session|SameSite)\b/i.test(serverText);
    const hasCsrfBoundary = /\b(?:csrf|xsrf|Origin|Referer|csrf_token)\b/i.test(serverText);
    if (hasStateChange && hasCookieSession && !hasCsrfBoundary) {
      const target = files.find(f=>/(?:server|api|backend|route|controller|worker|lambda)/i.test(f.path));
      findings.push(enrich({id:'CSRF-001',category:'CSRF',severity:'medium',title:'Cookie-authenticated state changes lack an obvious CSRF boundary',file:target?.path||'server-side code',line:1,evidence:'State-changing handlers and cookie/session indicators were found in server-side code, but no obvious CSRF token or Origin/Referer boundary was detected.',reason:'Cookie-authenticated state changes need a deliberate CSRF defense when cross-site requests could be accepted.',fix:'Use SameSite cookies appropriately and/or a robust CSRF token plus Origin/Referer validation for state-changing requests. Do not add CSRF protection to stateless bearer-auth endpoints unless their auth model requires it.',confidence:'medium',detectedBy:'project-signal'}));
    }

    // COOP/COEP are contextual hardening controls, not default vulnerabilities.
    const crossOriginIsolationNeed = /SharedArrayBuffer|cross-origin-isolated|Cross-Origin-Opener-Policy|Cross-Origin-Embedder-Policy/i.test(combinedText(files));
    if (crossOriginIsolationNeed && !/Cross-Origin-Opener-Policy/i.test(combinedText(files))) {
      findings.push(enrich({id:'PROJECT-COOP-001',category:'Browser Isolation',severity:'low',title:'Cross-origin isolation may be incomplete',file:htmlEntry?.path||'deployment configuration',line:1,evidence:'The project contains indicators that can benefit from cross-origin isolation, but no COOP header signal was detected.',reason:'Some powerful browser capabilities require deliberate cross-origin isolation.',fix:'Review COOP/COEP/CORP together before enabling them. This is contextual hardening, not a universal requirement.',confidence:'medium',detectedBy:'project-signal'}));
    }
  }

  function combinedText(files) { return files.map(f=>f.text||'').join('\n'); }

  function hasAnyPattern(text, patterns) {
    const hay = String(text || '').toLowerCase();
    return (patterns || []).some(p => hay.includes(String(p).toLowerCase()));
  }

  function countPatternHits(text, patterns) {
    const hay = String(text || '').toLowerCase();
    return (patterns || []).reduce((n,p) => {
      const needle = String(p).toLowerCase();
      if (!needle) return n;
      let at = hay.indexOf(needle), c = 0;
      while (at !== -1 && c < 50) { c++; at = hay.indexOf(needle, at + needle.length); }
      return n + c;
    }, 0);
  }

  function buildProjectIntelligence(files) {
    const teaching = KNOWLEDGE.teaching?.patterns || {};
    const all = combinedText(files);
    const lower = all.toLowerCase();
    const ext = new Set(files.map(f => f.ext || extOf(f.path || f.name || '')));
    const frameworks = [];
    if (ext.has('jsx') || ext.has('tsx') || /react(?:dom)?/.test(lower)) frameworks.push('React');
    if (ext.has('vue') || /(?:from|require).*vue/.test(lower)) frameworks.push('Vue');
    if (ext.has('svelte') || /sveltekit|@sveltejs/.test(lower)) frameworks.push('Svelte');
    if (ext.has('py') || /fastapi|flask|django/.test(lower)) frameworks.push('Python');
    if (/express|fastify|koa|hono|next\//.test(lower) || ext.has('js') || ext.has('ts')) frameworks.push('JavaScript/TypeScript');
    const servers = [];
    for (const [name, re] of [['Express','\bexpress\b'],['FastAPI','\bfastapi\b'],['Flask','\bflask\b'],['Django','\bdjango\b'],['Fastify','\bfastify\b'],['Hono','\bhono\b']]) if (new RegExp(re,'i').test(lower)) servers.push(name);
    const sanitizerHits = countPatternHits(all, teaching.safeBoundaries);
    const validationHits = countPatternHits(all, teaching.validationSignals);
    const sourceHits = countPatternHits(all, teaching.browserSources) + countPatternHits(all, teaching.serverSources);
    const sinkHits = countPatternHits(all, [...(teaching.htmlSinks||[]), ...(teaching.codeSinks||[]), ...(teaching.querySinks||[])]);
    const uploadSignals = countPatternHits(all, teaching.safeUploadSignals);
    const authSignals = countPatternHits(all, teaching.authBoundarySignals);
    const hasSecretBoundary = /process\.env|os\.getenv\s*\(|Deno\.env\.get\s*\(/i.test(all);
    const headerSignals = ['content-security-policy','referrer-policy','x-frame-options','x-content-type-options','cross-origin-opener-policy','cross-origin-embedder-policy'].filter(x => lower.includes(x));
    const auth = {
      present: /\b(?:login|signin|sign-in|authenticate|password|session|jwt|authorization|set-cookie)\b/i.test(all),
      secretTransport: /\b(?:set-cookie|sameSite|httponly|secure)\b/i.test(all),
      protectedBoundary: hasAnyPattern(all, teaching.authBoundarySignals)
    };
    const safeBoundaries = (teaching.safeBoundaries || []).filter(x => lower.includes(String(x).toLowerCase()));
    const trustSources = (teaching.browserSources || []).concat(teaching.serverSources || []).filter(x => lower.includes(String(x).toLowerCase())).slice(0, 20);
    return {
      frameworks:[...new Set(frameworks)], servers:[...new Set(servers)],
      signals:{sourceHits,sinkHits,sanitizerHits,validationHits,uploadSignals,authSignals,headerSignals:headerSignals.length},
      trustSources, safeBoundaries, headerSignals, hasSecretBoundary, auth,
      summary:{
        stack:[...new Set(frameworks.concat(servers))].join(', ') || 'Not confidently identified',
        auth:auth.present ? (auth.protectedBoundary ? 'Authentication signals found with a possible protection boundary' : 'Authentication/session signals found; protection boundary should be checked') : 'No clear authentication signals found',
        validation:validationHits ? `Validation controls detected (${validationHits} signal${validationHits===1?'':'s'})` : 'No obvious validation library/boundary detected',
        sanitization:sanitizerHits ? `Safety boundaries detected (${sanitizerHits} signal${sanitizerHits===1?'':'s'})` : 'No common sanitizer/encoding boundary detected',
        uploads:uploadSignals ? `Upload safety signals detected (${uploadSignals})` : 'No strong upload safety signal detected',
        secretBoundary:hasSecretBoundary ? 'Server-side environment/secret access detected' : 'No obvious server-side secret boundary detected'
      }
    };
  }

  function contextAround(text, index, radius=420) {
    const start=Math.max(0,index-radius), end=Math.min(text.length,index+radius);
    return text.slice(start,end);
  }

  function assessFinding(raw, file, hit, intelligence) {
    const f={...raw};
    const k=knowledgeFor(f);
    const context=contextAround(file.text, hit?.index ?? Math.max(0,(Number(f.line)||1)-1), 520);
    const localLower=context.toLowerCase();
    const rank={low:0,medium:1,high:2,critical:3};
    let confidence=f.confidence || 'medium';
    let advisory=!!f.advisory;
    let affectsScore=f.affectsScore;
    let evidenceTier='pattern';
    const cap=c=>{ if(rank[confidence]>rank[c]) confidence=c; };

    const localHas = (patterns=[]) => (patterns||[]).some(p => localLower.includes(String(p).toLowerCase()));

    if (f.id==='DOM-XSS-001') {
      const src=localHas(KNOWLEDGE.teaching?.patterns?.browserSources);
      const direct=/innerHTML\s*=\s*(?:[a-zA-Z_$][\w$]*|["'`]?\s*(?:location|URLSearchParams))/i.test(context);
      const safe=localHas(['textContent','DOMPurify','sanitizeHtml','escapeHtml','createTextNode']);
      if(safe) return null;
      if(src || direct){ evidenceTier='source-to-sink'; confidence=src&&direct?'high':'medium'; }
      else { advisory=true; affectsScore=false; confidence='low'; evidenceTier='sink-only'; }
    }

    if (f.id==='DOM-XSS-002') {
      const src=hit?.sourceIndex!=null || localHas(KNOWLEDGE.teaching?.patterns?.browserSources);
      const safe=localHas(['textContent','DOMPurify','sanitizeHtml','escapeHtml']);
      if(safe) return null;
      if(src){ evidenceTier='source-to-sink'; confidence='high'; }
      else { advisory=true; affectsScore=false; confidence='low'; evidenceTier='nearby-signal'; }
    }

    if (f.id==='UPLOAD-001') {
      const actualUpload=/(?:multipart|req\.files?|request\.files?|UploadFile|FormData|upload|write_bytes\s*\(|save\s*\()/i.test(context);
      const boundary=localHas(KNOWLEDGE.teaching?.patterns?.safeUploadSignals);
      const generatedName=localHas(['uuid','randomUUID','generated filename','hash']) && /(?:write|save|open|path\s*=)/i.test(context);
      if(!actualUpload) return null;
      if(boundary && generatedName) return null;
      confidence=boundary ? 'medium' : 'high';
      evidenceTier=boundary?'incomplete-upload-boundary':'upload-sink';
    }

    if (f.id==='PATH-002') {
      if(localHas(['safe_filename','secure_filename','sanitize_filename','basename']) && localHas(['uuid','randomUUID','hash']) && /(?:UPLOAD|UPLOAD_DIR|upload|output|storage)/i.test(context)) return null;
    }

    if (f.id==='AUTH-006') {
      const looksCredential=/[?&][a-zA-Z0-9_-]*(?:session|token|auth|jwt|sid)[a-zA-Z0-9_-]*=|\b(?:sessionId|session_id|accessToken|refreshToken|authToken)\b/i.test(context);
      if(!looksCredential || !intelligence.auth.present){ advisory=true; affectsScore=false; confidence='low'; evidenceTier='credential-like-url-signal'; }
      else evidenceTier='credential-in-url';
    }

    if (['API-INPUT-001','API-INPUT-002'].includes(f.id)) {
      if(localHas(KNOWLEDGE.teaching?.patterns?.validationSignals) || /(?:validate|parse|schema|safeParse|zod|joi|yup|pydantic)/i.test(context)) {
        advisory=true; affectsScore=false; confidence='low'; evidenceTier='validation-nearby';
      }
    }

    if (f.id==='INJECT-SQL-001' || f.id==='INJECT-SQL-002') {
      if(localHas(['parameterized','prepared statement','bind(', 'execute(', 'query_params','params:'])) {
        advisory=true; affectsScore=false; confidence='low'; evidenceTier='parameterized-nearby';
      } else if (localHas(KNOWLEDGE.teaching?.patterns?.serverSources)) {
        confidence = confidence==='critical'?'high':'medium'; evidenceTier='request-to-query';
      }
    }

    if (f.id==='CORS-002' && localHas(['allowlist','allowedOrigins','allowed origins','trustedOrigins','originAllowlist'])) {
      advisory=true; affectsScore=false; confidence='low'; evidenceTier='allowlist-nearby';
    }

    if (f.id==='COOKIE-001' && localHas(['secure','httponly','samesite'])) {
      // The rule itself decides only when at least one flag is absent. Keep it, but explicitly mark the partial boundary.
      evidenceTier='cookie-boundary';
    }

    if (k.confidenceCap) cap(k.confidenceCap);
    if(advisory) affectsScore=false;
    f.confidence=confidence; f.advisory=advisory; f.affectsScore=affectsScore; f.evidenceTier=evidenceTier;
    f.reasoning = evidenceTier==='source-to-sink' ? 'A plausible untrusted input was found near the dangerous operation.' : evidenceTier==='sink-only' ? 'The dangerous operation was found, but Orion did not find a convincing untrusted source nearby.' : evidenceTier==='validation-nearby' ? 'A validation boundary was found nearby, so this is a review item rather than a confirmed problem.' : undefined;
    return f;
  }

  function scoreFindings(findings) {
    let penalty = findings.reduce((sum,f)=> {
      if (f.affectsScore === false || f.advisory) return sum;
      if (['PROJECT-DEP-001','PROJECT-PRIV-001'].includes(f.id)) return sum;
      return sum + severityWeight[f.severity] * (f.confidence === 'high' ? 1 : f.confidence === 'medium' ? .7 : .45);
    },0);
    return Math.max(0, Math.min(100, Math.round(100 - Math.min(82, penalty))));
  }

  function compilePrompt(projectName, findings, files, intelligence) {
    const p = KNOWLEDGE.prompt || {};
    const header = p.preamble || 'You are a careful security engineer repairing an existing website. Verify every finding before changing code.';
    const constraints = p.constraints || [];
    if (!findings.length) {
      return [
        'ORION SECURITY REPAIR BRIEF',
        `Project: ${projectName}`,
        '',
        header,
        '',
        'Orion did not find a strong, evidence-backed security problem in the supplied source/config files.',
        'Do a conservative review anyway. Do not redesign the application or invent security controls without evidence.',
        '',
        'CHECK',
        'Authentication, access control, secrets, third-party scripts, uploads, redirects, deployment headers, logging, dependencies, and privacy behavior where applicable.',
        '',
        'VERIFICATION',
        p.verification || 'Run the existing build/tests and state what was checked.'
      ].join('\n');
    }

    const ordered = [...findings].sort((a,b)=>({critical:0,high:1,medium:2,low:3}[a.severity]-{critical:0,high:1,medium:2,low:3}[b.severity]));
    const fileNames = files.map(f=>f.path).slice(0,160).join('\n');
    const issueBlocks = ordered.filter(f=>!f.advisory).map((f,i)=>{
      const k = knowledgeFor(f);
      const verify = f.verify || k.verify || KNOWLEDGE.categories?.[f.category]?.verify || p.verification || 'Re-run the relevant tests and trace the original behavior after the fix.';
      const repair = f.plainFix || k.repair || f.fix || KNOWLEDGE.categories?.[f.category]?.repair || 'Review the affected code and apply the smallest safe fix.';
      return [
        `ISSUE ${i+1}`,
        `PLAIN-ENGLISH PROBLEM: ${f.plainTitle || f.title}`,
        `WHY IT MATTERS: ${f.plainWhy || f.reason}`,
        `SEVERITY: ${String(f.severity).toUpperCase()}`,
        `CONFIDENCE: ${f.confidence}`,
        `FILE: ${f.file}`,
        `LINE: ${f.line ?? '—'}`,
        `EVIDENCE:\n${f.evidence || 'No code excerpt captured.'}`,
        `REPAIR PLAYBOOK: ${repair}`,
        `VERIFY: ${verify}`,
        `EVIDENCE TIER: ${f.evidenceTier || 'pattern'}`,
        `ORION REASONING: ${f.reasoning || 'Review the surrounding code and verify the data flow before changing it.'}`,
        `TECHNICAL TAGS: ${f.id} | ${f.owasp || 'Context dependent'} | ${f.cwe || 'Context dependent'}`
      ].join('\n');
    }).join('\n\n');
    const reviewBlocks = ordered.filter(f=>f.advisory).map((f,i)=>[
      `REVIEW ITEM ${i+1}`,
      `CHECK: ${f.plainTitle || f.title}`,
      `WHY: ${f.plainWhy || f.reason}`,
      `WHERE: ${f.file}${f.line ? `:${f.line}` : ''}`,
      `DO NOT ASSUME THIS IS A VULNERABILITY: verify the deployment or full code flow first.`,
      `NEXT STEP: ${f.plainFix || f.fix || 'Review the flagged area before making changes.'}`
    ].join('\n')).join('\n\n');
    return [
      'ORION SECURITY REPAIR BRIEF',
      `Project: ${projectName}`,
      '',
      header,
      '',
      'GOAL',
      (p.promptPatterns?.userFacing || 'Explain each security issue in plain language before using technical terminology.'),
      'Repair only verified issues. Preserve the existing application, UI, routes, APIs, dependencies, and intended behavior.',
      '',
      'RULES FOR THE REPAIR AGENT',
      ...constraints.map((x,i)=>`${i+1}. ${x}`),
      '',
      'ORION REASONING SNAPSHOT',
      `Detected stack: ${intelligence?.summary?.stack || 'Not confidently identified'}`,
      `Authentication: ${intelligence?.summary?.auth || 'No clear authentication signals found'}`,
      `Validation: ${intelligence?.summary?.validation || 'Not assessed'}`,
      `Safety boundaries: ${intelligence?.summary?.sanitization || 'Not assessed'}`,
      `Upload handling: ${intelligence?.summary?.uploads || 'Not assessed'}`,
      `Secret boundary: ${intelligence?.summary?.secretBoundary || 'Not assessed'}`,
      `Trust sources observed: ${(intelligence?.trustSources || []).join(', ') || 'None confidently identified'}`,
      `Safe boundaries observed: ${(intelligence?.safeBoundaries || []).join(', ') || 'None confidently identified'}`,
      '',
      'SECURITY ISSUES TO VERIFY AND FIX',
      issueBlocks || 'None.',
      '',
      'REVIEW ITEMS — NOT CONFIRMED VULNERABILITIES',
      reviewBlocks || 'None.',
      '',
      'PROJECT FILE MAP',
      fileNames,
      '',
      'FINAL REPORT',
      'Return: changed files; what was changed for each finding; tests/build checks run; findings that were false positives or could not be verified; and any remaining manual-review risks.'
    ].join('\n');
  }


  function aggregateFindings(findings) {
    const map = new Map();
    for (const raw of findings) {
      const file = normalizeProjectPath(raw.file || '');
      const evidenceKey = String(raw.evidence || '').replace(/^\s*\d+\s*\|/gm,'').replace(/\s+/g,' ').trim().slice(0,240);
      const projectWide = raw.detectedBy === 'project-signal' || raw.file === 'deployment / response headers';
      const key = projectWide
        ? `${raw.id}|project`
        : raw.occurrence === 'per-file'
          ? `${raw.id}|${file}`
          : `${raw.id}|${file}|${raw.line}|${evidenceKey}`;
      const existing = map.get(key);
      if (!existing) {
        map.set(key,{...raw,file,occurrences:[{file,line:raw.line}]});
      } else {
        const token = `${file}:${raw.line}`;
        if (!existing.occurrences.some(o=>`${o.file}:${o.line}`===token)) existing.occurrences.push({file,line:raw.line});
      }
    }
    return [...map.values()].map(f=>{
      if (f.occurrences.length>1) f.repeatCount=f.occurrences.length;
      return f;
    });
  }

  function collapseRelatedFindings(findings) {
    const strong = findings.filter(f=>!f.advisory);
    const hasNear = (id,file,line,range=2) => strong.some(x=>x.id===id && x.file===file && Math.abs((Number(x.line)||0)-(Number(line)||0)<=range));
    return findings.filter(f=>{
      if (f.id==='DOM-XSS-001' && hasNear('DOM-XSS-002',f.file,f.line,2)) return false;
      if (f.id==='WEB-REDIRECT-002' && hasNear('WEB-REDIRECT-001',f.file,f.line,3)) return false;
      if (f.id==='CORS-003' && hasNear('CORS-001',f.file,f.line,5)) return false;
      if (f.id==='COOKIE-002' && hasNear('COOKIE-001',f.file,f.line,3)) return false;
      if (f.id==='INJECT-SQL-001' && hasNear('INJECT-SQL-002',f.file,f.line,3)) return false;
      return true;
    });
  }

  async function scan(files, onProgress) {
    const sourceFiles = canonicalizeFiles(files).filter(isTextFile).map(f => ({...f, text: normalizeText(f.text || ''), ext: extOf(f.name || f.path)}));
    const profile = projectProfile(sourceFiles);
    const intelligence = buildProjectIntelligence(sourceFiles);
    const findings = [];
    let processed = 0;
    const total = sourceFiles.length;
    for (const file of sourceFiles) {
      if (file.text.length > MAX_TEXT_BYTES) {
        findings.push(enrich({id:'FILE-001',category:'Analysis',severity:'low',title:'Large source file partially skipped',file:file.path,line:1,evidence:`${file.text.length.toLocaleString()} characters; analysis capped at ${MAX_TEXT_BYTES.toLocaleString()} characters for responsiveness.`,reason:'Very large files are capped in local analysis to protect browser responsiveness.',fix:'Review the skipped tail manually or analyze the file separately.',confidence:'high',detectedBy:'engine-limit'}));
        file.text = file.text.slice(0, MAX_TEXT_BYTES);
      }
      const lowerText = file.text.toLowerCase();
      for (const rule of rulesForExt(file.ext)) {
        const hits = matchesRule(rule, file.text, file.ext, lowerText);
        for (const hit of hits) {
          const loc = getLineSnippet(file.text, hit.index);
          const base=enrich({
            id:rule.id, category:rule.category, severity:rule.severity, title:rule.title,
            file:file.path, line:loc.line, evidence:loc.snippet, reason:rule.reason, fix:rule.fix,
            confidence: rule.confidenceBase || (rule.flow ? (hit.sourceIndex != null ? 'high' : 'medium') : (rule.severity==='critical'||rule.severity==='high' ? 'high' : 'medium')), detectedBy:'pattern', occurrence: rule.occurrence || 'per-location', advisory: !!rule.advisory
          });
          const assessed=assessFinding(base,file,hit,intelligence);
          if(assessed) findings.push(assessed);
        }
      }
      processed++;
      onProgress?.({processed,total,file});
      await new Promise(r=>typeof setTimeout==='function' ? setTimeout(r,0) : (typeof queueMicrotask==='function' ? queueMicrotask(r) : r()));
    }
    addProjectSignals(findings, sourceFiles, profile);
    const deduped = collapseRelatedFindings(aggregateFindings(findings));
    return {findings:deduped, files:sourceFiles.map(({path,name,size,ext})=>({path,name,size,ext})), profile, intelligence, score:scoreFindings(deduped), prompt:compilePrompt('Untitled project',deduped,sourceFiles,intelligence)};
  }

  function makeTestProject() {
    return [
      {path:'site/index.html',name:'index.html',size:1040,text:`<!doctype html>\n<html><head><title>Demo Shop</title><script src="https://cdn.example.com/widget@latest.js"></script></head><body><a href="https://example.com" target="_blank">Shop</a><input name="email"><script src="http://cdn.demo.dev/app.js"></script></body></html>`},
      {path:'site/app.js',name:'app.js',size:1800,text:`const token = localStorage.getItem('token');\nconst next = new URLSearchParams(location.search).get('next');\nconst profile = localStorage.getItem('profile');\ndocument.querySelector('#name').innerHTML = new URLSearchParams(location.search).get('name');\nwindow.location = next;\nconsole.log('token', token);`},
      {path:'site/api/login.js',name:'login.js',size:2600,text:`export async function login(req, res){\n  const { email, password } = req.body;\n  console.log('password', password);\n  const user = await db.query(\`SELECT * FROM users WHERE email = '\${email}'\`);\n  const jwt = sign({id:user.id}, 'my-hard-coded-signing-key-123456789');\n  res.cookie('session', jwt, { sameSite:'None' });\n  return res.json({ok:true});\n}`},
      {path:'site/package.json',name:'package.json',size:480,text:`{"scripts":{"postinstall":"node install-hook.js"},"dependencies":{"demo":"^1.0.0"}}`}
    ];
  }

  window.OrionEngine = {RULES, scan, compilePrompt, makeTestProject, TEXT_EXT, SKIP_EXT, canonicalizeFiles, buildProjectIntelligence};
})();
