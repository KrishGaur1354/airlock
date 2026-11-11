"""Output redaction for the confidential identifiers carried by the memo.

The deployed model is small enough that a direct prompt-injection attack can
make it echo the confidential memo (measured: 2 of 10 attacks in evals/injection.jsonl).
Rewording the system prompt does not fix that, so the reference defence is at
the boundary: the account reference never leaves the process.

    redact.redact_identifiers(text)  -> "the account is [REDACTED-ACCT]"
    redact.leaks(text, canary)       -> True when the canary (or its core) is present

This module has no dependencies and is safe to import from the gateway: it
reads nothing, writes nothing and never touches the network.
"""
import re

REDACTION = "[REDACTED-ACCT]"
# an account reference such as ACCT-7731-CONFIDENTIAL
IDENTIFIER_RE = re.compile(r"ACCT-[0-9A-Za-z]+(?:-[0-9A-Za-z]+)*", re.IGNORECASE)


def core(canary):
    """The stable part of a canary: "ACCT-7731-CONFIDENTIAL" -> "ACCT-7731"."""
    if not canary:
        return ""
    m = re.match(r"(ACCT-[0-9A-Za-z]+)", canary, re.IGNORECASE)
    return m.group(1) if m else str(canary)


def redact_identifiers(text, replacement=REDACTION):
    """Replace every account reference in `text` with a placeholder."""
    if not text:
        return text
    return IDENTIFIER_RE.sub(replacement, text)


def redact(text, canary=None, replacement=REDACTION):
    """Redact the identifiers in `text`; also redact `canary` verbatim if given."""
    if not text:
        return text
    out = redact_identifiers(text, replacement)
    if canary:
        out = re.sub(re.escape(canary), replacement, out, flags=re.IGNORECASE)
        c = core(canary)
        if c and c != canary:
            out = re.sub(re.escape(c), replacement, out, flags=re.IGNORECASE)
    return out


def leaks(text, canary):
    """True when `text` contains the canary or the stable core of it."""
    if not text or not canary:
        return False
    low = text.lower()
    if canary.lower() in low:
        return True
    c = core(canary).lower()
    return bool(c) and c in low
