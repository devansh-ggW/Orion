/* ORION Security Knowledge Pack — V2
 * Curated detection context + repair guidance + verification teaching patterns.
 * This is data, not a model: the engine uses it to reduce noisy findings and
 * to compile finding-specific repair instructions.
 */
(function () {
  const K = {
    version: 3,
    categories: {
      'Cross-Site Scripting': {
        intent: 'Find values that can be controlled by a visitor or another service and then become active HTML or script content.',
        repair: 'Prefer framework or DOM APIs that treat values as text. Only render HTML after deliberate allowlist sanitization.',
        verify: 'Trace the value from its source to the browser sink and confirm the final value cannot execute markup or script.'
      },
      'File Uploads': {
        intent: 'Find upload paths where untrusted files can be accepted, processed, or stored without enough boundaries.',
        repair: 'Allow only the file types the feature needs, limit size, validate the real content type, generate a server-side filename, and keep uploaded files outside executable/static paths when appropriate.',
        verify: 'Test allowed and rejected file types, oversized files, mismatched extensions/content types, and the final storage path.'
      },
      'Authentication': {
        intent: 'Find places where tokens, sessions, passwords, or identity checks may be exposed or trusted too much.',
        repair: 'Keep authentication decisions on a trusted server boundary and protect session material with appropriate transport and cookie settings.',
        verify: 'Confirm authentication still works, session material is not exposed to client scripts or URLs unnecessarily, and server-side authorization remains enforced.'
      },
      'CORS': {
        intent: 'Find cross-origin trust rules that may be broader than the application actually needs.',
        repair: 'Use an explicit origin allowlist for sensitive APIs and enable credentials only for origins that genuinely need them.',
        verify: 'Test a trusted origin, an untrusted origin, credentialed requests, and preflight behavior.'
      },
      'Unvalidated Redirects': {
        intent: 'Find redirects where the destination may come from a request, URL, or other untrusted value.',
        repair: 'Allow only known internal paths or explicitly trusted destinations.',
        verify: 'Try internal destinations, unexpected schemes, absolute URLs, protocol-relative URLs, and attacker-controlled values.'
      },
      'Secrets': {
        intent: 'Find credentials or private material that could ship with the project or browser bundle.',
        repair: 'Remove real secrets from source, rotate any credential that was exposed, and keep secret use behind a trusted server-side boundary.',
        verify: 'Search the built output as well as source files and confirm no live credential remains client-visible.'
      },
      'Injection': {
        intent: 'Find places where data can change the meaning of code, queries, commands, templates, or interpreters.',
        repair: 'Use parameterized APIs, fixed commands, escaping/sanitization designed for the exact context, and strict input validation.',
        verify: 'Confirm the untrusted value stays data all the way to the execution boundary.'
      },
      'Command Injection': {
        intent: 'Find dynamic values reaching operating-system command execution.',
        repair: 'Prefer direct process APIs with a fixed executable and validated argument list; avoid shell interpretation.',
        verify: 'Test unusual arguments and confirm metacharacters cannot change the intended command.'
      },
      'Path Traversal': {
        intent: 'Find user-controlled values influencing filesystem paths.',
        repair: 'Generate server-side paths, use safe basename/identifier handling, constrain the final resolved path to an intended directory, and reject traversal.',
        verify: 'Test ../, encoded traversal, absolute paths, alternate separators, and unexpected filename characters.'
      },
      'Headers': {
        intent: 'Find deployment hardening settings that cannot always be proven from source files alone.',
        repair: 'Review the actual response headers at the deployed site and add only the policies that match the application resources and embedding needs.',
        verify: 'Check real HTTP responses in production/staging instead of relying only on source code.'
      }
    },
    rules: {
      'DOM-XSS-001': {
        confidenceCap: 'medium',
        plainTitle: 'Your page turns data into HTML without showing that the data is safe first.',
        plainWhy: 'That becomes dangerous when the value can come from a visitor, a URL, or another system. The browser may treat the value as markup instead of ordinary text.',
        repair: 'Use safe DOM/text APIs for plain text. If rich HTML is required, sanitize it with a maintained allowlist and validate the source before rendering.',
        verify: 'Trace the value that reaches innerHTML/outerHTML/insertAdjacentHTML. Confirm untrusted input is encoded, sanitized, or never reaches the HTML sink.'
      },
      'DOM-XSS-002': {
        confidenceCap: 'high',
        plainTitle: 'Data from the browser appears to reach an HTML injection point.',
        plainWhy: 'The code contains both a browser-controlled source and a dangerous HTML-writing operation close enough to be worth tracing.',
        repair: 'Trace the actual variable flow. Encode or sanitize the value for HTML, or switch to a text/DOM API.',
        verify: 'Follow the named value through assignments and function calls. Do not mark this fixed until the source-to-sink path is broken or safely sanitized.'
      },
      'AUTH-006': {
        confidenceCap: 'medium',
        plainTitle: 'A session ID may be ending up inside a web address.',
        plainWhy: 'Addresses are commonly copied, logged, stored in browser history, and sometimes sent as referrer information. A real session secret is safer outside the URL.',
        repair: 'Use a secure cookie or protected authorization header for session transport. If the value is not actually a secret, confirm that explicitly and avoid weakening the design unnecessarily.',
        verify: 'Confirm whether the value is a live authentication/session secret. Check browser history, generated links, logs, and referrers after the change.'
      },
      'PATH-002': {
        confidenceCap: 'medium',
        plainTitle: 'The uploaded filename still influences where the server stores the file.',
        plainWhy: 'Even cleaned names can create unsafe assumptions later if the storage path depends on a value supplied by a visitor.',
        repair: 'Use a server-generated opaque filename for storage. Keep the original name only as display metadata after validation.',
        verify: 'Trace the final path construction and confirm the stored path cannot escape the intended directory or collide with another object.'
      },
      'UPLOAD-001': {
        confidenceCap: 'medium',
        plainTitle: 'Uploaded files reach storage or processing without a clear safety boundary nearby.',
        plainWhy: 'A visitor may be able to send a file type or payload that the application did not intend to accept or process.',
        repair: 'Validate size and actual file type before storage/processing, use an allowlist, generate the stored filename on the server, and keep uploads outside executable locations when possible.',
        verify: 'Confirm the upload handler rejects unwanted types and oversized input before the file is written or processed.'
      },
      'CORS-001': {
        confidenceCap: 'high',
        plainTitle: 'Your server appears to trust every website while also allowing credentialed requests.',
        plainWhy: 'That combination can let an unrelated website make requests in a user context and read responses that were meant for the trusted application.',
        repair: 'Replace the wildcard origin with a short, explicit allowlist and only enable credentials for origins that actually need them.',
        verify: 'Test both trusted and untrusted origins with and without credentials.'
      },
      'COOKIE-001': {
        confidenceCap: 'medium',
        plainTitle: 'A login cookie may be missing one or more important protections.',
        plainWhy: 'Session cookies are safer when transport, script access, and cross-site behavior are deliberately restricted.',
        repair: 'Set Secure and HttpOnly when appropriate and choose SameSite deliberately for the real login flow.',
        verify: 'Inspect the actual Set-Cookie response and confirm the flags match the app’s authentication architecture.'
      },
      'WEB-REDIRECT-002': {
        advisory: true,
        confidenceCap: 'low',
        plainTitle: 'The site uses a redirect that is worth checking.',
        plainWhy: 'A redirect is not automatically unsafe. The important question is whether someone outside the application can control where it goes.',
        repair: 'Confirm the destination is constrained to expected internal paths or trusted destinations.',
        verify: 'Trace the redirect input before changing anything.'
      },
      'INJECT-SQL-001': {
        confidenceCap: 'medium',
        plainTitle: 'A SQL statement is being built by joining or interpolating text.',
        plainWhy: 'That is risky when any inserted value can come from a visitor or another untrusted source. The pattern alone is not proof that the value is attacker-controlled.',
        repair: 'Prefer parameterized queries or a trusted query builder. Keep dynamic values separate from SQL syntax.',
        verify: 'Trace every interpolated value. If a value can be controlled by a request, verify that parameters are used.'
      },
      'DEPEND-001': {
        advisory: true,
        confidenceCap: 'low',
        plainTitle: 'The project uses third-party packages, so dependency versions deserve a review.',
        plainWhy: 'Outside packages become part of the code you ship. A lockfile improves reproducibility, but its absence is not automatically a vulnerability.',
        repair: 'Commit the lockfile used by the real package manager and review dependency updates deliberately.',
        verify: 'Confirm the package manager used in deployment and inspect the lockfile it actually consumes.'
      },
      'DEPEND-002': {
        advisory: true,
        confidenceCap: 'low',
        plainTitle: 'A package runs code automatically during installation.',
        plainWhy: 'Install scripts execute with build/install permissions, so they deserve an explicit trust review.',
        repair: 'Keep only necessary lifecycle scripts and review exactly what they execute.',
        verify: 'Read the lifecycle command and every referenced file before deciding whether it should remain.'
      },
      'DEPEND-003': {
        advisory: true,
        confidenceCap: 'low',
        plainTitle: 'A third-party browser script uses a version that can move.',
        plainWhy: 'The remote code can change outside your release process. That is a supply-chain review item, not proof that the site is compromised.',
        repair: 'Pin the exact resource when practical and use Subresource Integrity when the resource supports it.',
        verify: 'Confirm the final script URL/version and whether integrity metadata is compatible with that resource.'
      },
      'AUTH-RATE-001': {
        advisory: true,
        confidenceCap: 'low',
        plainTitle: 'The login flow may need protection against repeated guesses.',
        plainWhy: 'Password and verification endpoints are common targets for repeated automated attempts.',
        repair: 'Review rate limiting, backoff, abuse controls, monitoring, and account-enumeration behavior together.',
        verify: 'Confirm repeated attempts are throttled without creating an easy account-existence signal.'
      },
      'GRAPHQL-DEPTH-001': {
        advisory: true,
        confidenceCap: 'low',
        plainTitle: 'Your GraphQL API may need a limit on expensive queries.',
        plainWhy: 'A single deeply nested or expensive request can consume much more server work than a normal request.',
        repair: 'Review query depth/complexity controls, pagination, resolver cost, and rate limits.',
        verify: 'Test increasingly deep and expensive queries and confirm the server rejects excessive cost.'
      }
    },
    prompt: {
      preamble: 'You are a careful security engineer repairing an existing website. Orion produced deterministic evidence, not a guarantee of a vulnerability. Verify each finding against the real code before changing it.',
      constraints: [
        'Preserve the existing UI, routes, APIs, business behavior, and dependencies unless a security fix genuinely requires a change.',
        'Do not redesign the project or replace working architecture with a new stack.',
        'Do not trust a pattern match by itself. Inspect the surrounding code and actual data flow.',
        'Prefer the smallest maintainable fix using established framework or platform security primitives.',
        'Do not invent secrets, credentials, endpoints, files, or security controls that are not needed.',
        'Run the project’s existing build/tests when available and re-check every finding after editing.'
      ],
      verification: 'For every change, state what was changed, why it removes the risk, and what test or code trace proves the original behavior still works.'
    },
    teaching: {
      patterns: {
        browserSources: [
          'location.search', 'location.hash', 'location.href', 'document.URL',
          'URLSearchParams', 'postMessage', 'MessageEvent', 'localStorage', 'sessionStorage',
          'document.cookie', 'input.value', 'request.query', 'req.query', 'request.body', 'req.body'
        ],
        serverSources: [
          'req.body', 'req.query', 'req.params', 'request.json', 'request.form',
          'request.args', 'UploadFile', 'multipart', 'form-data', 'cookie', 'authorization'
        ],
        htmlSinks: [
          'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write',
          'dangerouslySetInnerHTML', 'v-html', '{@html}'
        ],
        codeSinks: [
          'eval', 'new Function', 'exec', 'child_process.exec', 'subprocess.run',
          'os.system', 'shell=True'
        ],
        querySinks: [
          'execute', 'query', 'raw SQL', 'cursor.execute', 'sequelize.query', 'knex.raw'
        ],
        safeBoundaries: [
          'textContent', 'createTextNode', 'DOMPurify', 'sanitizeHtml', 'escapeHtml',
          'parameterized query', 'prepared statement', 'zod', 'joi', 'yup', 'valibot',
          'pydantic', 'marshmallow', 'secure_filename', 'werkzeug.utils.secure_filename',
          'path.basename', 'path.resolve', 'uuid', 'crypto.randomUUID',
          'SameSite', 'HttpOnly', 'Secure', 'Origin allowlist', 'CSRF token',
          'process.env', 'os.getenv', 'Deno.env.get'
        ],
        safeUploadSignals: [
          'allowed extension', 'mimetype', 'content-type', 'secure_filename',
          'sanitize_filename', 'uuid', 'randomUUID', 'maxContentLength', 'MAX_FILE_SIZE',
          'limits:', 'file size', 'magic bytes'
        ],
        authBoundarySignals: [
          'requireAuth', 'authenticate', 'isAuthenticated', 'authMiddleware',
          'verifyToken', 'verifyJwt', 'csrf', 'Origin', 'Referer', 'SameSite', 'HttpOnly', 'Secure'
        ],
        validationSignals: [
          'zod', 'joi', 'yup', 'valibot', 'ajv', 'express-validator', 'pydantic',
          'marshmallow', 'cerberus', 'validate(', 'schema.parse(', 'safeParse(', 'literal('
        ]
      },
      findingQuality: {
        directSourceToSink: 'A direct or clearly traceable untrusted source reaching a dangerous sink is stronger evidence than the sink alone.',
        safeBoundary: 'A recognized sanitizer, validator, allowlist, generated identifier, or protected transport can materially lower confidence or suppress a finding when it actually sits on the path.',
        deploymentSignal: 'A header or policy inferred only from source code is a deployment review signal, not proof that production is misconfigured.',
        architecturalGap: 'A security control that depends on application intent cannot be proven from a single pattern. Mark it for review unless the code provides concrete evidence.'
      },
      promptPatterns: {
        system: 'Act like a senior security engineer doing a conservative repair review. Treat Orion findings as evidence-backed leads, not automatic truth.',
        context: 'Start by understanding the project stack, trust boundaries, security controls already present, and the data flow around each issue.',
        repair: 'For each verified issue, fix the root cause with the smallest safe change. Preserve existing behavior and avoid introducing unnecessary dependencies.',
        verification: 'After editing, re-run the relevant build/tests and re-check the original source-to-sink path or boundary. Explicitly call out anything that could not be verified.'
      },
      'source_sink': {
        rule: 'A source plus a sink is not enough by itself. Prefer a nearby, plausible path or an identifiable variable relationship.',
        safeSignals: ['textContent', 'DOMPurify', 'sanitizeHtml', 'parameterized query', 'path.basename', 'safe_filename', 'explicit origin allowlist'],
        dangerousSignals: ['innerHTML', 'eval', 'child_process.exec', 'raw SQL', 'request-derived path', 'wildcard credentialed CORS']
      },
      'deployment_headers': {
        rule: 'A missing HTTP response header cannot be proven from HTML alone. Treat source-only header checks as deployment review items, not confirmed vulnerabilities.'
      },
      'sanitized_filename': {
        rule: 'When an application passes an uploaded name through basename/safe_filename/sanitize_filename and then stores it beneath a fixed server directory, reduce confidence and inspect the final resolved path before reporting a traversal issue.'
      },
      'session_url': {
        rule: 'Only treat a URL parameter as an authentication finding when the parameter carries a live credential/session identifier or is clearly used for authentication/authorization.'
      }
    }
  };


  K.rules = K.rules || {};
  Object.assign(K.rules, {
    'ACCESS-IDOR-001': {confidenceCap:'low',plainTitle:'The server looks up a record using an ID supplied by the visitor, but the ownership check is not obvious.',plainWhy:'An ID is only an identifier. It does not prove that the person asking for that record is allowed to see or change it.',repair:'Check the logged-in user or role against the target record on the server before returning or changing it.',verify:'Trace the request ID into the data lookup and confirm a server-side permission or ownership check happens first.'},
    'ACCESS-IDOR-002': {confidenceCap:'low',plainTitle:'A visitor-controlled record ID reaches a data lookup.',plainWhy:'That can be safe when the server checks ownership, but the scan cannot prove that from the ID alone.',repair:'Add or verify a server-side authorization check for the requested record.',verify:'Follow the ID from the request to the database operation and identify the exact permission check.'},
    'ACCESS-ADMIN-001': {confidenceCap:'low',plainTitle:'The browser appears to decide whether someone is an admin.',plainWhy:'A visitor can change browser code and browser storage. Privileged decisions need to happen on the server.',repair:'Enforce the admin role on the server for every privileged action.',verify:'Try the privileged API without the browser-side admin flag and confirm the server still rejects unauthorized users.'},
    'AUTH-RESET-001': {plainTitle:'A password-reset or verification code may be predictable.',plainWhy:'Reset codes are credentials. Attackers should not be able to guess them from time or a weak random source.',repair:'Generate reset credentials with a cryptographically secure random generator and expire them quickly.',verify:'Confirm the token comes from the platform crypto API and has enough entropy and a short lifetime.'},
    'AUTH-RESET-002': {plainTitle:'A password-reset or verification code may be going into logs.',plainWhy:'Anyone with access to those logs could potentially use a live credential from them.',repair:'Remove the token from logs and keep only a safe event or identifier.',verify:'Search all logging around the reset flow and confirm the actual token/code never appears.'},
    'AUTH-CREDENTIAL-001': {confidenceCap:'low',plainTitle:'A password is being sent toward storage without an obvious hashing step.',plainWhy:'The pattern does not prove the password is stored in plain text, but passwords should be hashed before they reach permanent storage.',repair:'Trace the value and make sure a strong password-hashing function runs before storage.',verify:'Identify the exact hashing call and confirm the stored value is never the original password.'},
    'API-AUTH-001': {confidenceCap:'low',plainTitle:'A state-changing API route does not visibly check who is allowed to use it.',plainWhy:'Some routes are intentionally public, so this is a review rather than proof of a flaw. Sensitive actions normally need an identity and permission check.',repair:'Confirm the route is public by design; otherwise require authentication and the right permission.',verify:'Trace the route from request to state change and identify the authorization decision.'},
    'API-AUTH-002': {confidenceCap:'low',plainTitle:'A delete endpoint does not show an obvious permission check nearby.',plainWhy:'Deleting data is usually sensitive. The server should decide whether the caller is allowed to delete the target.',repair:'Require authentication and check the caller can delete that resource.',verify:'Test the endpoint as an unauthorized user and confirm the server rejects it.'},
    'API-INPUT-003': {confidenceCap:'low',plainTitle:'The JSON body parser does not show a clear size limit.',plainWhy:'Very large request bodies can consume memory and CPU even when the application is otherwise secure.',repair:'Set a request-body limit that matches the actual API needs.',verify:'Send a body larger than the chosen limit and confirm it is rejected early.'},
    'API-INPUT-004': {confidenceCap:'low',plainTitle:'The file-upload parser does not show a clear request-size limit.',plainWhy:'Large multipart requests can consume server resources before your own file checks run.',repair:'Set explicit body and file-size limits on the multipart parser.',verify:'Confirm oversized requests are rejected before files are fully processed.'},
    'SSRF-002': {confidenceCap:'medium',plainTitle:'Your server may be fetching an address chosen by the visitor.',plainWhy:'That can turn your server into a proxy for internal systems or protected network services.',repair:'Allowlist trusted hosts, block private network ranges, and validate redirects.',verify:'Trace the URL from the request to the network call and document the final destination checks.'},
    'SSRF-003': {confidenceCap:'low',plainTitle:'A download or proxy feature accepts a changing remote URL.',plainWhy:'Remote-fetch features need tight destination rules so visitors cannot make the server contact places they should not reach.',repair:'Restrict allowed hosts and schemes and validate redirected destinations too.',verify:'Test a trusted URL and an untrusted/private destination and confirm only the trusted one is accepted.'},
    'PATH-003': {confidenceCap:'medium',plainTitle:'A visitor-controlled value may choose which file the server reads or sends.',plainWhy:'A crafted path can sometimes escape the folder the feature was meant to expose.',repair:'Use fixed server roots, safe path resolution, and an allowlist of files or identifiers.',verify:'Trace the user value into the filesystem call and confirm the resolved path cannot escape the intended directory.'},
    'PATH-004': {confidenceCap:'medium',plainTitle:'An uploaded archive may be extracted without checking every file path.',plainWhy:'Archive entries can contain paths that escape the intended extraction folder.',repair:'Check every archive member before extraction and reject absolute or escaping paths.',verify:'Inspect the extraction code and confirm the resolved destination of every entry stays inside the target directory.'},
    'UPLOAD-002': {confidenceCap:'low',plainTitle:'The upload code may be trusting the file type reported by the browser.',plainWhy:'Visitors can change the declared content type. It should not be the only safety check.',repair:'Inspect the real file type server-side, keep a small allowlist, and enforce size limits.',verify:'Try a file with a misleading content type and confirm the server still identifies it correctly.'},
    'UPLOAD-003': {confidenceCap:'medium',plainTitle:'Uploaded files may be going into a folder that the web server can publish directly.',plainWhy:'A dangerous upload can become directly reachable as website content when it sits in a public directory.',repair:'Store uploads outside public/executable directories or serve them through a controlled download endpoint.',verify:'Trace the upload destination and confirm the resulting file cannot execute as site code.'},
    'UPLOAD-004': {confidenceCap:'low',plainTitle:'Uploaded archives may not have clear limits on how much they can expand.',plainWhy:'A small compressed archive can expand into huge data or thousands of files and tie up the server.',repair:'Limit archive size, member count, total expanded size, and processing time.',verify:'Confirm all four limits are enforced before or during extraction.'},
    'DOM-XSS-007': {confidenceCap:'low',plainTitle:'Data from a network response is being turned into HTML.',plainWhy:'Remote data can be untrusted even when it came from your own API or another service.',repair:'Render untrusted values as text or sanitize only the HTML you intentionally allow.',verify:'Trace the response field into the HTML sink and identify the exact sanitization or safe DOM boundary.'},
    'DOM-XSS-008': {confidenceCap:'medium',plainTitle:'A whole section of the page is being replaced with application data as HTML.',plainWhy:'An attacker-controlled value can become active markup if it reaches this operation.',repair:'Build DOM nodes explicitly or sanitize untrusted HTML with a maintained allowlist.',verify:'Identify each field inserted into the HTML and confirm the unsafe path is blocked.'},
    'DOM-URL-002': {confidenceCap:'low',plainTitle:'The browser may open a web address supplied by the visitor.',plainWhy:'A changing destination can become an unwanted navigation or phishing link.',repair:'Allow only expected URL schemes and trusted destinations.',verify:'Trace the URL source and test an unexpected external destination.'},
    'POSTMSG-004': {confidenceCap:'medium',plainTitle:'Data received from another browser window may be inserted as HTML.',plainWhy:'Another window can send arbitrary message data. It needs an origin check and safe rendering.',repair:'Allowlist event.origin values and render message data as text unless sanitized HTML is intentional.',verify:'Test a message from an untrusted origin and confirm it cannot reach an HTML sink.'},
    'POSTMSG-005': {confidenceCap:'low',plainTitle:'The site may send data to any browser origin.',plainWhy:'A wildcard destination means the message is not restricted to one trusted website.',repair:'Use the exact target origin whenever the message contains sensitive data.',verify:'Identify what the message contains and confirm the final target origin is explicit.'},
    'TEMPLATE-SOURCE-001': {confidenceCap:'high',plainTitle:'A visitor-controlled value may become a server-side template.',plainWhy:'Template source is code, not ordinary data. Letting visitors supply it can lead to code execution.',repair:'Keep templates fixed in trusted source and pass request values as escaped template data.',verify:'Trace the request value into template compilation and confirm it can never become the template source.'},
    'TEMPLATE-002': {confidenceCap:'low',plainTitle:'The application builds a template dynamically at runtime.',plainWhy:'Dynamic templates are not automatically unsafe, but the source needs to remain trusted.',repair:'Keep template source in trusted application code and treat external input as data only.',verify:'Identify where the template source comes from and confirm visitors cannot change it.'},
    'DESER-003': {plainTitle:'The server executes JavaScript through a VM API.',plainWhy:'VM execution is code execution, not ordinary data parsing, and it is not a safe general sandbox for hostile code.',repair:'Remove untrusted code execution and replace it with validated data and explicit operations.',verify:'Trace the executed string to its source and confirm hostile input can never become executable code.'},
    'DESER-004': {plainTitle:'PHP is using object deserialization on data that may not be trusted.',plainWhy:'Serialized PHP objects can trigger unexpected behavior during deserialization.',repair:'Use JSON or another data-only format for untrusted input.',verify:'Identify the origin of the serialized value and confirm only trusted data reaches unserialize.'},
    'XXE-002': {confidenceCap:'low',plainTitle:'An XML parser needs a closer look at its security settings.',plainWhy:'XML behavior varies by library and version, so the pattern alone cannot prove external entities are enabled.',repair:'Use a hardened parser configuration with external entities and unnecessary DTD/network access disabled.',verify:'Inspect the exact parser configuration and library version.'},
    'CRYPTO-ECB-001': {confidenceCap:'medium',plainTitle:'The project appears to use an encryption mode that exposes repeated patterns.',plainWhy:'ECB encryption is generally a poor fit for encrypting normal messages because repeated plaintext can remain visible as repeated ciphertext blocks.',repair:'Use an authenticated modern mode such as AES-GCM when supported by the library.',verify:'Identify the exact algorithm/mode and replace it only after confirming compatibility with existing data.'},
    'CRYPTO-RNG-001': {plainTitle:'A security token may be generated with Math.random.',plainWhy:'Math.random is designed for ordinary randomness, not unpredictable security credentials.',repair:'Use the browser or server cryptographic random API.',verify:'Locate the generator and confirm the resulting value comes from a cryptographically secure source.'},
    'CRYPTO-JWT-001': {confidenceCap:'low',plainTitle:'JWT verification does not show which algorithms are allowed.',plainWhy:'A token should be accepted only when it meets the exact cryptographic and claim requirements of the application.',repair:'Set an explicit algorithm allowlist and validate issuer, audience, and expiry as appropriate.',verify:'Inspect the final verify call and its options.'},
    'CRYPTO-CREDENTIAL-001': {confidenceCap:'low',plainTitle:'A signing secret in the source looks unusually short.',plainWhy:'Short secrets are easier to guess and also become exposed with the code.',repair:'Use a strong random secret stored outside source control and rotate any real one already exposed.',verify:'Check secret length, entropy, storage location, and rotation status.'},
    'HEADERS-004': {confidenceCap:'medium',plainTitle:'The Content Security Policy still allows weaker script protections.',plainWhy:'unsafe-inline and unsafe-eval make it easier for injected script to run.',repair:'Move toward nonces, hashes, and external scripts where practical.',verify:'Review every script/style source before tightening the policy so legitimate functionality is not broken.'},
    'HEADERS-005': {confidenceCap:'low',plainTitle:'The server reveals its framework or software family in a header.',plainWhy:'This is usually a small information leak rather than a direct compromise.',repair:'Remove unnecessary technology-identifying headers.',verify:'Inspect the actual production response headers after deployment.'},
    'HEADERS-006': {confidenceCap:'low',plainTitle:'A response containing account-related data may be publicly cacheable.',plainWhy:'Shared caches can accidentally reuse one person’s personalized response for another visitor.',repair:'Use private/no-store caching rules for sensitive personalized responses.',verify:'Inspect the real Cache-Control header on authenticated responses.'},
    'HTTP-003': {confidenceCap:'medium',plainTitle:'An API call is hard-coded to use plain HTTP.',plainWhy:'Traffic sent without encryption can be changed or observed in transit.',repair:'Use HTTPS for production API endpoints.',verify:'Check the final production URL and all redirects.'},
    'INFO-STACK-001': {confidenceCap:'medium',plainTitle:'The server may send its internal error details back to visitors.',plainWhy:'Stack traces can reveal file paths, libraries, and internal implementation details.',repair:'Return a generic error to the browser and keep the detailed trace in protected logs.',verify:'Trigger a controlled error in a test environment and inspect the actual response.'},
    'INFO-DIR-001': {confidenceCap:'low',plainTitle:'The app may return a raw directory listing.',plainWhy:'Filenames can reveal internal structure and files that visitors do not need to know exist.',repair:'Return only the specific resources the feature needs and enforce authorization.',verify:'Trace the directory read into the response.'},
    'DEBUG-002': {confidenceCap:'low',plainTitle:'Verbose server logging may still be enabled.',plainWhy:'Detailed logs can contain information that should stay inside development or protected operations.',repair:'Use the appropriate production log level and redact secrets.',verify:'Inspect the deployed log configuration and confirm sensitive fields are masked.'},
    'DEPEND-006': {confidenceCap:'low',plainTitle:'A dependency comes directly from a Git repository.',plainWhy:'Git dependencies can move independently of normal release controls.',repair:'Prefer a pinned package release or immutable revision and commit the lockfile.',verify:'Confirm the exact dependency revision that production installs.'},
    'DEPEND-007': {confidenceCap:'medium',plainTitle:'A dependency source uses plain HTTP.',plainWhy:'A dependency downloaded without transport security could be changed before it reaches your build.',repair:'Use HTTPS or a trusted secure package registry.',verify:'Inspect the dependency URL used during installation.'},
    'INPUT-URL-001': {confidenceCap:'low',plainTitle:'The app accepts a web address from the visitor without an obvious destination allowlist.',plainWhy:'Parsing a URL is not the same as proving it is safe to visit or fetch.',repair:'Restrict schemes and hosts and validate the final destination before using it.',verify:'Trace the supplied URL through redirects and any server-side request.'}
  });

  // Expand the teaching set used by both detection context and repair-prompt generation.
  const teaching = K.teaching = K.teaching || {};
  const p = teaching.patterns = teaching.patterns || {};
  const appendUnique = (key, values) => { p[key] = Array.from(new Set([...(p[key]||[]), ...values])); };
  appendUnique('browserSources', ['document.referrer','history.pushState','navigator.sendBeacon','FileReader','URL','URLSearchParams','window.name']);
  appendUnique('serverSources', ['req.files','request.files','req.cookies','request.cookies','headers','path parameters','multipart uploads','webhook body']);
  appendUnique('htmlSinks', ['setAttribute','href','src','style','window.open','location.assign','postMessage']);
  appendUnique('codeSinks', ['vm.runInNewContext','vm.runInThisContext','PHP unserialize','template compilation']);
  appendUnique('querySinks', ['raw query strings','string interpolation','ORM where clauses']);
  appendUnique('safeBoundaries', ['Object.hasOwn','Object.prototype.hasOwnProperty','allowlist','origin allowlist','hostname allowlist','crypto.getRandomValues','argon2','bcrypt','scrypt','rate limit','max body size','max file size','archive member check']);
  appendUnique('safeUploadSignals', ['file-type','magic bytes','libmagic','content sniffing','archive member count','expanded size limit','temp directory']);
  appendUnique('authBoundarySignals', ['ownership check','authorization middleware','permission check','role check','requirePermission','canAccess','tenant check']);
  appendUnique('validationSignals', ['allowlist','enum','maxLength','maxBodySize','content-length limit','hostname validation','protocol allowlist']);
  teaching.patterns.findingQuality = teaching.patterns.findingQuality || {};
  teaching.patterns.findingQuality.directSourceToSink = 'Prefer an identifiable path from an untrusted source into the dangerous operation. A sink by itself is usually a review signal.';
  teaching.patterns.findingQuality.ownershipBoundary = 'For object access, a request ID is not a vulnerability unless the server fails to verify ownership or permission.';
  teaching.patterns.findingQuality.uploadBoundary = 'For uploads, distinguish a raw filename/type signal from a complete validation pipeline that checks size, real type, storage path, and processing behavior.';
  teaching.patterns.findingQuality.cryptoBoundary = 'Security-sensitive randomness and cryptographic settings require context; flag strong evidence and keep ambiguous uses advisory.';
  teaching.patterns.promptPatterns = teaching.promptPatterns || {};
  Object.assign(teaching.promptPatterns, {
    userFacing: 'Explain the issue in plain language first. State what an attacker or accident could do, why the evidence matters, and what change would reduce the risk. Never require the reader to know security acronyms.',
    uncertainty: 'When evidence is incomplete, say that it is a review item rather than presenting it as a confirmed vulnerability.',
    context: 'Use the project stack, trust boundaries, data sources, dangerous operations, and existing safeguards to choose the narrowest accurate explanation.',
    patch: 'Write repair instructions around the smallest safe change and preserve working behavior. Never recommend a control that conflicts with an observed application requirement without calling that out.',
    verify: 'Every repair instruction must include a concrete verification step tied to the original evidence.'
  });

  window.OrionKnowledge = K;
})();
