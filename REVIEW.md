# Review log (Claude verifies OpenCode output)

## audit.py — APPROVED
- 20 unit tests pass; py_compile OK; no 3.7+ syntax; matches contract (GENESIS, canonical_json, hash formula).
- Note (inherent to hash chains): truncating the *tail* of the log is not detectable by `verify` alone. Mitigation idea: evidence.py records the head hash
  at each collection so a later shorter log is flagged. Not blocking.

## controls.py / oscal.py / report.py — APPROVED (2 minor notes)
- 59 tests pass; no 3.7+ syntax; SSP/POA&M render from *live* evidence with no unfilled placeholders and no CDN refs; POA&M has one row per fail/unknown.
- Note 1 (controls.py:5): docstring mentions "GMI Cloud". It is only a comment and controls.py never reads the key, but oscal/report (high side) import it. Please reword to "the vendor LLM" so `grep -rn GMI airlock/` shows only vendor_gmi.py and cli.py.
- Note 2 (oscal.py): result has `findings[]` (with target-id/status.state) but no `observations[]` at result level; the contract allowed either, so not blocking. Add observations[] linking evidence strings if time permits.

## OpenCode batch 2 (evals, redact, sbom/scan, vendor_gmi, dashboard, tamper, demo, audit anchor) — APPROVED with caveats
- 141 tests pass; GMI grep on gateway/evidence/bundle clean; `cli.py` is the only consumer of vendor_gmi (lazy import in `build --enrich`).
  Fixed a contradiction: OpenCode's isolation test forbade any `vendor_gmi` mention, but its own HANDOFF asked for the cli import. Test now allows only a lazy (indented) import in cli.py.
- Measured on this board: served replies 10/10 non-leak, raw model alone 7/10. AI-EVAL = pass on the served number, detail states both.
- CAVEAT (honest): redact.py strips `ACCT-...` identifiers only. The 1.7B model still echoes the rest of the memo (borrower, rating) on INJ-01/02/05; the 100% is relative to the canary. Do not present it as general exfiltration protection.
- CAVEAT: all 13 lowside/cache entries are `origin: local-fallback`; GMI Cloud has not actually been called (no key yet). Say "vendor enrichment path built and cached fallback", not "GMI-generated".
