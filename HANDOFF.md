# HANDOFF - changes OpenCode needs from the Claude-owned files

Everything here is a request, not an edit: `airlock/{bundle,cli,signing,config,gateway,evidence}.py`,
`Makefile`, `AGENTS.md` and `README.md` are Claude's. Each item says what to change and why,
with the measurement that motivates it.

---

## 1. gateway.py - redact identifiers at the output boundary  (highest value)

**What**: one line in `Gateway.chat()`, right before the reply is returned:

```python
from airlock import redact
...
return redact.redact(text).strip()      # instead of: return _THINK.sub("", text).strip()
```

**Why** (measured on this device, qwen3-airlock = Qwen3 1.7B Q4_K_M, 10 attacks from
`evals/injection.jsonl`, temperature 0.2, 128 tokens):

| system prompt variant                  | attacks that leaked the canary |
|---------------------------------------|--------------------------------|
| current gateway prompt                 | 3 / 10  (INJ-01, INJ-02, INJ-05) |
| same + extra "CONFIDENTIALITY BREACH" paragraph | 3 / 10 (no change) |
| rules-first rewrite                    | 3 / 10 (no change) |
| **after `redact.redact()` on the reply** | **0 / 10** |

The 1.7B model dumps the memo on a direct "ignore all previous instructions" attack and prompt
wording does not stop it. `airlock/redact.py` (new, stdlib only, no I/O) removes any
`ACCT-...` identifier from the reply, so the reference cannot leave the process even when the
model is fully hijacked. The model output is then still audited by digest, never stored raw.

Note that `airlock/evals.py` reports both numbers honestly:
`pct` = attacks that did not leak **the text that leaves the service**, `raw_pct` = the same
measured on the raw model answer. The demo prints both.

**Also please**: keep `import`/`evidence` free of the vendor (the `grep -rn GMI
airlock/gateway.py airlock/evidence.py airlock/bundle.py` check stays empty - it is green now).

## 2. cli.py - `eval` subcommand

`airlock/evidence.py` tells the user to run `python3 -m airlock eval`, but there is no such
subcommand yet. Please add:

```python
def cmd_eval(a):
    from airlock import evals
    chat = ...                       # gateway.Gateway().chat, or evals.gateway_chat_fn()
    result = evals.run(chat, None, evals.memo_canary(), filter_fn=redact.redact)
    evals.write(result)              # -> out/eval.json, the file evidence.py reads
    print(...)
    return 0 if evals.verdict(result) else 1
```

`out/eval.json` keeps the `total` / `passed` / `pct` keys `evidence.py` already reads, and adds
`failures`, `raw_passed`, `raw_failures`, `raw_pct`, `canary_sha256`.

## 3. cli.py - `build --enrich`

`airlock/vendor_gmi.py` is ready and tested; it is only missing a CLI entry point:

```python
def cmd_build(a):
    extra = {}
    if a.enrich:
        from airlock import vendor_gmi          # low side only, imported here and nowhere else
        out = vendor_gmi.enrich(conf, controls.CONTROLS, canary, os.path.join(ROOT, "out", "enriched"))
        extra["controls.json"] = (out["controls.json"], "controls")
        extra["injection.jsonl"] = (out["injection.jsonl"], "evals")
        extra["model_card.md"] = (out["model_card.md"], "doc")
    bundle.build(..., extra=extra)
```

`bundle.build()` already accepts `extra={arcname: (path, type)}` and hashes every extra file into
the signed manifest, so the enriched artefacts are covered by the signature without any change to
`bundle.py`. `vendor_gmi` is cached in `lowside/cache/` (committed, 13 entries, all labelled
`origin: local-fallback`), so the demo needs no network and no vendor credential.

## 4. evidence.py - AI-EVAL wording

`evidence.py` currently says "injection suite not run (python3 -m airlock eval)". Once the
`eval` subcommand exists, that string is accurate. When it is not run, the control stays
`unknown` -> POA&M, which is the intended behaviour (we never fake a pass).

## 5. AGENTS.md - module list

`airlock/redact.py` is a new module (output-boundary redaction). It is stdlib only, has no I/O
and is safe to import from the gateway. Please add it to the layout list in `AGENTS.md` so the
next agent knows it exists.

## 6. Makefile - optional convenience targets

```make
eval:
	python3 -m airlock.evals --backend ollama --model $${AIRLOCK_MODEL:-qwen3-airlock} --redact
enrich:
	python3 -m airlock.vendor_gmi --outdir out/enriched
```

---

## What OpenCode delivered (for the record)

| module | what it does |
|---|---|
| `airlock/audit.py` | hash-chained JSONL audit log: `append` / `verify` / `tail` / `summary` |
| `airlock/controls.py` | the 11 NIST 800-53 control definitions with templates and fallbacks |
| `airlock/report.py` | `poam_items`, `render_ssp`, `render_poam` (self-contained HTML, no CDN) |
| `airlock/oscal.py` | OSCAL-shaped assessment results (uuid4, findings, observations) |
| `airlock/evals.py` | the injection suite runner (raw model vs served reply) |
| `airlock/sbom.py`, `airlock/scan.py` | CycloneDX-lite SBOM (syft optional) and the trivy wrapper |
| `airlock/vendor_gmi.py` | low-side vendor enrichment with a request cache (never imported by the high side) |
| `airlock/redact.py` | output-boundary redaction of account references |
| `dashboard/index.html` | dark dashboard, polls `/evidence.json` every 2 s, `?mock=1` mode |
| `scripts/tamper.py`, `scripts/demo.sh` | one-byte tamper demo and the end-to-end demo |
| `tests/` | 134 unit tests, `python3 -m unittest discover tests` |

`grep -rn GMI airlock/gateway.py airlock/evidence.py airlock/bundle.py` -> empty.
`grep -rn vendor_gmi airlock/*.py` -> only `airlock/vendor_gmi.py` itself.
