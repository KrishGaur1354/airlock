# Airlock — agent build guide (condensed)

Hackathon c0mpiled-18 Taipei, build window 6:45-10:45 PM. Optimize for a 90-second demo.
One-liner: signed offline AI bundles that verify themselves on an air-gapped Jetson and generate
their own NIST 800-53 accreditation evidence (OSCAL-shaped results, SSP, POA&M).

## Hard rules
1. No pip/npm/apt installs without approval. Stdlib first; `cryptography` only (jinja2/rich absent) with stdlib/openssl fallbacks.
2. No sudo, no system packages, never stop/restart Ollama or llama-server without asking.
3. Low memory (7.4 GB shared). No torch, no docker builds. Model context 2048.
4. Keep Python 3.6-compatible: no walrus, match, dataclasses, f-string `=`.
5. Commit small and often. Never rewrite history.
6. Happy path first, then tamper demo, then polish.
7. Missing syft/trivy/cosign are not errors: record as unknown control -> POA&M.

## Environment
Jetson Orin Nano (R36.4.3), aarch64, Python 3.10.12. Model `qwen3:1.7b` via Ollama (Q4_K_M); upgrade qwen3:4b, fallback qwen3:0.6b. R32 (orig Nano): llama.cpp CPU-only + Qwen3-0.6B-Q4_K_M, NEVER Ollama; llama.cpp build timeboxed 25 min, no CUDA build on R32; if it fails use the laptop as the edge device and say so. Backend via AIRLOCK_BACKEND
(ollama http://127.0.0.1:11434/api/chat | llamacpp http://127.0.0.1:8080/v1/chat/completions), model in AIRLOCK_MODEL.
Prepend `/no_think` to the system prompt for Qwen3 only (omit for Qwen2.5). Gateway :8000. Config: airlock.conf (KEY=VALUE, hand-parsed).

## Layout
airlock/{cli,bundle,signing,sbom,scan,gateway,audit,evidence,controls,oscal,report,evals,redact,vendor_gmi}.py  (redact = stdlib output-boundary filter used by gateway)
templates/ dashboard/ data/memo.txt evals/injection.jsonl scripts/{tamper.py,demo.sh} keys/ out/ lowside/cache/

## Bundle (*.airlock = tar)
manifest.json, manifest.sig (ed25519 over exact manifest bytes), model.gguf, sbom.cdx.json, scan.json,
evals.json, controls.json, model_card.md (optional). Hash big files in 1 MB chunks.
Manifest fields: name, version, created, target{arch,device,min_mem_gb,l4t_release}, model{file,family,params,quant,license,source},
artifacts[{path,sha256,bytes,type}], policy{license_allowlist,max_critical_cves}, controls_claimed[].

## CLI
python3 -m airlock {keygen|build|verify|import|serve|evidence|audit-verify}. Exit 1 on failure and name the failing artifact.
`import` verifies BEFORE extracting to the install location.

## Gateway
stdlib http.server + ThreadingMixIn. POST /v1/chat (X-Airlock-Key; 401 + audit on bad key), GET /probe (egress),
/evidence.json, /export/{ssp.html,poam.html,assessment-results.json}, / -> dashboard.
Audit: out/audit.jsonl {ts,user,prompt_sha256,response_sha256,status,prev_hash,hash}; never store raw prompts.

## Controls
SI-7, CM-8, CM-2, RA-5, SR-3/SR-4, SC-7, AU-2/AU-9, AC-3, AI-EVAL. Collector -> {control,title,status pass|fail|unknown,evidence,observed_at,detail}.
fail/unknown -> POA&M {id,control,weakness,remediation,milestone_date(today+30d),status:open}. Call output "OSCAL-shaped".

## GMI Cloud (vendor side ONLY)
OpenAI-compatible POST https://api.gmi-serving.com/v1/chat/completions, `Authorization: Bearer $GMI_API_KEY`, model $GMI_MODEL, stdlib urllib.
`airlock/vendor_gmi.py`, used only by `airlock build --enrich`: per-control implementation-statement templates ({status},{evidence},{observed_at})
-> controls.json; 20 injection/exfil prompts -> evals/injection.jsonl; model_card.md. Cache every response in lowside/cache/*.json
(max ~50 calls, temperature 0.3, max_tokens 800). Outputs go INSIDE the bundle (hashed + signed). If unreachable, fall back to hand-written templates.
High side (import/gateway/evidence) must never import vendor_gmi or read GMI_API_KEY; `grep -r GMI airlock/gateway.py airlock/evidence.py` must be empty.

## Milestones
7:10 scaffold+keygen+hashing+backend reachable | 8:00 build/verify/import | 8:45 gateway | 9:30 collectors+reports |
9:50 dashboard+tamper, feature freeze | 10:15 README+video | 10:40 submit.
Non-negotiables: signature verify, offline inference, egress probe, tamper rejection, SSP export.

## Added in guide v2
- Licenses: all Qwen3 dense + Qwen2.5 0.5B/1.5B are Apache-2.0. Qwen2.5-3B is NOT (Qwen Research License) -> must fail the SR-3 license gate (negative test).
- Generation cap 128 tokens (num_predict / max_tokens), temperature 0.2. Pre-warm the model with one request at `serve` startup.
- Small models are weak against injection: keep memo short, system prompt firm, AI-EVAL threshold >=80% non-leak, NEVER fake a pass.
- Provenance (SR-4): model.source must be the real origin (hf://... or ollama:qwen3:1.7b when extracted from a blob). Always record sha256; read `quant` from filename/GGUF header, do not assume.
- Enriched bundles also carry controls.json, evals/injection.jsonl, model_card.md, all in `artifacts` and signed.
- GMI: commit cached outputs (lowside/cache) so the demo never needs network. GMI_API_KEY lives only in the laptop's airlock.conf; `make deploy` excludes airlock.conf and keys/airlock.key.
  Check: `grep -rn GMI airlock/gateway.py airlock/evidence.py airlock/bundle.py` returns nothing.
- report.py fills controls.json templates with OBSERVED evidence; missing template -> plain default sentence. LLM writes wording, collectors supply facts.
- CM-2 also records measured runtime facts (backend, GPU used or not via tegrastats sample if available).
