# ORION — Security Intent Engine V1

Local-first website security analyzer and plain-English repair-instruction compiler. No database, no R2, and no AI inference required for the core V1 scan.

## Run

Open `index.html` directly in a modern Chromium browser, or serve the folder with any static server.

## What is real in V1

- Folder/multi-file upload
- ZIP upload with a browser-side ZIP reader
- ZIP entry-count and expanded-size guards
- Local source/config filtering
- 1005 deterministic security/privacy/configuration checks
- Separate versioned `knowledge.js` pack for plain-English findings, trust-boundary teaching patterns, safe-pattern signals, repair playbooks, verification instructions, and prompt composition rules
- Source-to-sink checks for selected data-flow patterns
- Framework-aware XSS checks for React, Vue, and Svelte
- Project-level checks for headers, privacy signals, lockfiles, and cookie-authenticated state changes
- Severity + confidence + evidence + file/line location
- Security posture score that avoids double-counting project-level advisories
- Generated repair prompt compiled from actual findings and rule-specific repair/verification playbooks; advisory review items are separated from issues to fix
- Copy prompt, save prompt, JSON report, reset
- No persistent source-code storage
- Interactive CSS 3D Orion core with lightweight hover parallax + drag rotation
- Reduced-motion fallback and lightweight visual effects for older hardware
- Cloudflare Worker health endpoint scaffold only; no fake analysis backend

## Security boundary

This is static analysis. It does not prove a site is secure, does not attempt exploitation, and does not perform deep testing against arbitrary remote URLs. A future remote-scan feature should require ownership verification before active/deeper analysis.

## Architecture

`ZIP / files -> browser unpack/filter -> deterministic rules -> project context -> findings -> prompt compiler -> coding AI -> re-upload -> re-scan`

The core engine intentionally does not depend on a local LLM. An external coding AI can receive the generated repair brief and make the code changes; ORION can then independently re-check the repaired project.

## Test

From this folder:

```bash
node tests/test-engine.js
```

The test suite checks rule-pack integrity, vulnerable and safe fixtures, upload handling, and project-level CSRF behavior.

## Next stage

- Replace selected regex-only checks with AST-aware parsing
- Expand versioned rule packs and CWE mappings
- Add structured remediation/verification templates for each rule
- Add GitHub repository import and changed-file-only rescans
- Add ownership verification before any remote URL/deep-scan capability
- Move only compute-heavy analysis to Cloudflare Workers/Workflows when scale requires it
- Keep source data ephemeral; do not add R2/D1 unless a concrete workflow needs persistence


## Latest V1 quality pass
- Adds a structured project-intelligence pass that maps likely trust sources, dangerous sinks, validation/sanitization boundaries, auth signals, framework/server hints, and secret boundaries before findings are ranked.
- Uses the same reasoning snapshot to compile a more context-aware repair brief, so the external coding AI receives the project stack, existing controls, evidence tier, and verification direction.
- Keeps the Orion identity mark larger and turns the 3D core into the same icon used by the product.
- Replaces continuously rotating 3D layers with pointer-driven transforms to reduce idle CPU/GPU work.
- Reduces false positives by requiring nearby source-to-sink evidence for selected data-flow rules.
- Treats deployment-only header checks, dependency hygiene checks, and similar hardening signals as review items instead of confirmed vulnerabilities.
- Avoids redundant findings when a stronger contextual rule already explains the same root cause.
- Cookie flag checks inspect the same local code context instead of using a fragile negative regex.
- Dependency rules are restricted to their relevant manifest/file types.
- Repair prompts are assembled from rule-specific playbooks rather than a single fixed prompt.
- Added an Orion SVG identity mark used as the favicon and brand icon.
- File/ZIP selection and folder selection now use separate real browser inputs.
- 1005 deterministic rules/checks with integrity checks.
- Canonicalizes archive roots and removes mirrored duplicate trees.
- Groups noisy upload-sink findings per file instead of per matched line.
- Treats filename sanitization signals such as `safe_filename()` / `basename()` as a context boundary for PATH-002.
- Detects auth/session context from source content as well as filenames.
- Keeps project-wide response-header checks separate from per-file findings.
- Browser-side ZIP limits remain enabled for local-only processing.
