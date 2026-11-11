# Review log (Claude verifies OpenCode output)

## audit.py — APPROVED
- 20 unit tests pass; py_compile OK; no 3.7+ syntax; matches contract (GENESIS, canonical_json, hash formula).
- Note (inherent to hash chains): truncating the *tail* of the log is not detectable by `verify` alone. Mitigation idea: evidence.py records the head hash
  at each collection so a later shorter log is flagged. Not blocking.

## controls.py / oscal.py / report.py — APPROVED (2 minor notes)
- 59 tests pass; no 3.7+ syntax; SSP/POA&M render from *live* evidence with no unfilled placeholders and no CDN refs; POA&M has one row per fail/unknown.
- Note 1 (controls.py:5): docstring mentions "GMI Cloud". It is only a comment and controls.py never reads the key, but oscal/report (high side) import it. Please reword to "the vendor LLM" so `grep -rn GMI airlock/` shows only vendor_gmi.py and cli.py.
- Note 2 (oscal.py): result has `findings[]` (with target-id/status.state) but no `observations[]` at result level; the contract allowed either, so not blocking. Add observations[] linking evidence strings if time permits.
