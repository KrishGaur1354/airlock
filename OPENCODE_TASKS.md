# OpenCode task sheet (Claude owns the critical path and verifies your work)

Read AGENTS.md first. Stdlib only, Python 3.6-compatible (no walrus/match/dataclasses/f"{x=}").
Commit small, one module per commit, message `module: what`. Never rewrite history. No installs, no sudo.
Tests: stdlib `unittest` in `tests/test_<module>.py`; run `python3 -m unittest discover tests`.

## Ownership (do NOT edit files you don't own)
| Owner | Files |
|---|---|
| Claude | airlock/{bundle,cli,signing,config,gateway,evidence}.py, Makefile, AGENTS.md, README.md |
| OpenCode | airlock/{audit,controls,oscal,report,evals,sbom,scan,vendor_gmi}.py, templates/*, dashboard/index.html, evals/injection.jsonl, scripts/{tamper.py,demo.sh}, tests/** |
Need a change in a Claude file? Write it in `HANDOFF.md` (what + why), don't edit.

## Shared data shapes (the contract)
- canonical_json(x) = json.dumps(x, sort_keys=True, separators=(",", ":"))
- Audit entry: {ts, user, prompt_sha256, response_sha256, status, prev_hash, hash}; GENESIS prev_hash = "0"*64;
  hash = sha256_hex(prev_hash + canonical_json(entry_without_hash)).
- Control result: {control, title, status: "pass"|"fail"|"unknown", evidence: [str], observed_at: ISO8601Z, detail: str}
- evidence.json: {generated, bundle: {name, version, signer_fingerprint, target: {...}},
  device: {arch, l4t_release, ram_mb, backend, model}, controls: [Control result...],
  audit: {ok: bool, entries: int, tail: [hash, ...last 5]}, summary: {satisfied, total, si7_failed: bool}}
- POA&M item: {id, control, weakness, remediation, milestone_date (today+30d, YYYY-MM-DD), status: "open"}

## Tasks (in priority order)
1. tests/fixtures/evidence.sample.json (all-pass) and evidence.tampered.json (SI-7 fail, RA-5 unknown). FIRST, everything else uses them.
2. audit.py: `append(path, user, prompt_sha256, response_sha256, status) -> entry` (create file if missing, thread-safe via a module Lock),
   `verify(path) -> (ok: bool, count: int, bad_index: int|None)`, `tail(path, n=5) -> [entry]`. Tests: clean chain, flipped byte, deleted line.
3. controls.py: `CONTROLS` = list of {id, title, family, how_verified, remediation, template} for SI-7, CM-8, CM-2, RA-5, SR-3, SR-4,
   SC-7, AU-2, AU-9, AC-3, AI-EVAL. `template` uses {status}, {evidence}, {observed_at}. `get(id)`. These are also the --enrich fallback.
4. report.py: `poam_items(evidence, today=None) -> [POA&M]` (one per fail/unknown), `render_ssp(evidence, statements=None) -> str`,
   `render_poam(items) -> str`. statements = optional {control_id: template}; missing -> controls.py template; missing -> plain default.
   Fill templates with OBSERVED evidence via str.format_map (safe on missing keys). jinja2 optional, stdlib path must work. Self-contained HTML, no CDN.
5. oscal.py: `build(evidence) -> dict` OSCAL-shaped assessment-results (results[].findings[]/observations[], uuid4 ids,
   target.target-id = control id, status.state satisfied|not-satisfied). Label "OSCAL-shaped", not "valid OSCAL".
6. dashboard/index.html: vanilla JS, no CDN, dark. Polls /evidence.json every 2s. Green banner "ACCREDITATION EVIDENCE: N/M controls satisfied",
   RED banner when summary.si7_failed. Control card grid, device card, audit tail (last 5 hashes + chain status), buttons to
   /export/ssp.html, /export/poam.html, /export/assessment-results.json, chat box POST /v1/chat with X-Airlock-Key field. Must work with a
   `?mock=1` query that loads tests/fixtures-style JSON from /evidence.json.
7. evals.py + evals/injection.jsonl: 10 hand-written attacks {id, prompt}. `run(chat_fn, path, canary) -> {total, passed, pct, failures:[id]}`;
   an attack passes if canary not in reply. Fixed seed, no network. NEVER fake a pass.
8. sbom.py: `generate(model_path, model_meta) -> dict` CycloneDX-lite (use syft if on PATH). scan.py: `scan(path) -> {status: "unavailable"|"ok", tool, criticals: int|None, detail}`; trivy missing -> "unavailable".
9. scripts/tamper.py: `python3 scripts/tamper.py IN.airlock` -> out/<name>.tampered.airlock; extract tar to a temp dir, flip ONE byte at fixed offset 4096 in model.gguf, re-tar with the original manifest/sig untouched. Print what changed.
10. vendor_gmi.py (LAST, low side only): `enrich(conf, controls, canary, outdir) -> {"controls.json": path, "injection.jsonl": path, "model_card.md": path}`.
   stdlib urllib POST https://api.gmi-serving.com/v1/chat/completions, Bearer $GMI_API_KEY, model $GMI_MODEL, temperature 0.3, max_tokens 800.
   Cache each response in lowside/cache/<sha256 of request>.json; cache hit = no network; hard cap 50 uncached calls; on any error fall back to controls.py templates.
   Must NOT be imported by anything except cli.py's build path. `grep -rn GMI airlock/gateway.py airlock/evidence.py airlock/bundle.py` must stay empty.
11. scripts/demo.sh: keygen -> build -> verify -> import -> evidence -> serve, `set -e`, echo each step.

## Verification handshake
After each commit Claude reviews with: unit tests, a 3.6-syntax check (`python3 -m py_compile`, grep for `:=`/`match`/`dataclass`),
contract conformance, and the GMI-isolation grep. Findings land in `REVIEW.md`; fix them before moving to the next task.
