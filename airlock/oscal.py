"""OSCAL-shaped assessment results for the evidence bundle.

IMPORTANT: the output is OSCAL-*shaped*. It follows the structure and vocabulary
of the NIST OSCAL assessment-results model (uuid4 identifiers, metadata,
results -> findings -> observations, target/status/state) closely enough to be
read by an OSCAL-aware tool, but it is NOT a validated or certified OSCAL
document: it is not schema-validated, not signed with an OSCAL JSON signature
and not backed by the full OSCAL component-definition catalogue.

Every document and every finding carries the marker prop:

    {"name": "shape", "value": "OSCAL-shaped"}
"""
import datetime
import time
import uuid

from airlock import controls

SHAPE = "OSCAL-shaped"
OSCAL_VERSION = "1.0.0"
DOC_VERSION = "0.1.0"
OBSERVATION_LIFETIME_DAYS = 365

STATE_BY_STATUS = {
    "pass": "satisfied",
    "fail": "not-satisfied",
    "unknown": "not-satisfied",
}
IMPLEMENTATION_BY_STATUS = {
    "pass": "implemented",
    "fail": "not-implemented",
    "unknown": "partial",
}


def _uuid():
    return str(uuid.uuid4())


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _shape_prop():
    return [{"name": "shape", "value": SHAPE}]


def _expire(observed_at):
    try:
        base = datetime.datetime.strptime(observed_at, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        base = datetime.datetime.utcnow()
    return (base + datetime.timedelta(days=OBSERVATION_LIFETIME_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(value):
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "; ".join([str(v) for v in value])
    return str(value)


def _observation(control_result, party_uuid):
    """One observation per control, carrying the observed evidence strings."""
    observed_at = control_result.get("observed_at", "")
    evidence = control_result.get("evidence", [])
    if isinstance(evidence, str):
        evidence = [evidence]
    relevant = []
    for item in evidence:
        relevant.append({"href": "#" + str(control_result.get("control", "")),
                         "description": str(item)})
    return {
        "uuid": _uuid(),
        "title": "Observed state of %s" % control_result.get("control", ""),
        "description": control_result.get("detail", "") or
                       "Control %s evaluated as %s." % (control_result.get("control", ""),
                                                        control_result.get("status", "unknown")),
        "methods": ["TEST", "EXAMINE"],
        "types": ["finding"],
        "collected": observed_at or _now(),
        "expires": _expire(observed_at),
        "props": _shape_prop(),
        "relevant-evidence": relevant,
        "links": [{"href": "#party-%s" % party_uuid, "rel": "actor"}],
    }


def _finding(control_result, party_uuid):
    status = control_result.get("status", "unknown")
    state = STATE_BY_STATUS.get(status, "not-satisfied")
    return {
        "uuid": _uuid(),
        "title": "%s (%s)" % (control_result.get("control", ""),
                              control_result.get("title", controls.title(control_result.get("control", "")))),
        "description": control_result.get("detail", "") or
                       "Control %s evaluated as %s." % (control_result.get("control", ""), status),
        "props": _shape_prop(),
        "origins": [{"actors": [{"type": "party", "actor-type": "party",
                                 "actor-uuid": party_uuid}]}],
        "target": {
            "type": "objective-id",
            "target-id": control_result.get("control", ""),
            "status": {"state": state, "reason": status},
            "implementation-status": IMPLEMENTATION_BY_STATUS.get(status, "partial"),
        },
        "observations": [_observation(control_result, party_uuid)],
    }


def _result_observation(evidence, party_uuid):
    """Result-level observation: what was examined at assessment level."""
    bundle = evidence.get("bundle", {}) or {}
    device = evidence.get("device", {}) or {}
    audit = evidence.get("audit", {}) or {}
    evidence_strings = []
    if bundle.get("signer_fingerprint"):
        evidence_strings.append("bundle %s v%s signed by %s"
                                % (bundle.get("name", "-"), bundle.get("version", "-"),
                                   bundle.get("signer_fingerprint")))
    if device:
        evidence_strings.append("assessed on %s / %s / %s MB RAM"
                                % (device.get("backend", "-"), device.get("model", "-"),
                                   device.get("ram_mb", "-")))
    evidence_strings.append("audit chain %s over %s entries"
                            % ("verified" if audit.get("ok") else "BROKEN", audit.get("entries", 0)))
    return {
        "uuid": _uuid(),
        "title": "Assessment context",
        "description": "The controls below were assessed against the signed bundle on the "
                       "deployment target using measured facts only.",
        "methods": ["EXAMINE"],
        "types": ["statement"],
        "collected": evidence.get("generated") or _now(),
        "expires": _expire(evidence.get("generated")),
        "props": _shape_prop(),
        "relevant-evidence": [{"href": "#evidence-%s" % party_uuid, "description": s}
                              for s in evidence_strings],
        "links": [{"href": "#party-%s" % party_uuid, "rel": "actor"}],
    }


def build(evidence):
    """Build the OSCAL-shaped assessment-results document from an evidence dict."""
    evidence = evidence or {}
    bundle = evidence.get("bundle", {}) or {}
    device = evidence.get("device", {}) or {}
    summary = evidence.get("summary", {}) or {}
    audit = evidence.get("audit", {}) or {}
    generated = evidence.get("generated") or _now()

    party_uuid = _uuid()
    doc_uuid = _uuid()
    result_uuid = _uuid()

    findings = []
    for c in evidence.get("controls", []):
        if not isinstance(c, dict):
            continue
        findings.append(_finding(c, party_uuid))

    total = summary.get("total", len(findings))
    satisfied = summary.get("satisfied", len([f for f in findings
                                               if f["target"]["status"]["state"] == "satisfied"]))

    return {
        "assessment-results": {
            "uuid": doc_uuid,
            "metadata": {
                "title": "Airlock assessment results for %s" % bundle.get("name", "bundle"),
                "last-modified": generated,
                "version": DOC_VERSION,
                "oscal-version": OSCAL_VERSION,
                "remarks": "This document is OSCAL-shaped: it mirrors the OSCAL assessment-results "
                           "structure but is not a validated or signed OSCAL document.",
                "props": _shape_prop(),
                "roles": [{
                    "id": "assessor",
                    "title": "Airlock assessor",
                    "description": "Automated collector running on the deployment target.",
                }],
                "parties": [{
                    "uuid": party_uuid,
                    "type": "organization",
                    "name": "Airlock",
                    "short-name": "airlock",
                }],
            },
            "results": [{
                "uuid": result_uuid,
                "title": "Assessment of bundle %s v%s" % (bundle.get("name", "-"),
                                                           bundle.get("version", "-")),
                "description": "Controls assessed on the deployment target against the signed bundle "
                               "%s." % bundle.get("signer_fingerprint", "-"),
                "start": generated,
                "end": generated,
                "props": _shape_prop(),
                "reviewed-controls": {
                    "control-selections": [{"how-many": "all"}],
                    "remarks": "NIST SP 800-53 controls claimed by the bundle manifest.",
                },
                "findings": findings,
                "observations": [_result_observation(evidence, party_uuid)],
                "remarks": "%s of %s controls satisfied; audit chain %s."
                           % (satisfied, total, "verified" if audit.get("ok") else "BROKEN"),
            }],
            "back-matter": {
                "remarks": "Device: %s / %s / %s MB RAM. Evidence generated %s."
                           % (device.get("backend", "-"), device.get("model", "-"),
                              device.get("ram_mb", "-"), generated),
            },
        }
    }


def findings(evidence):
    """Convenience accessor: the findings list of the single result."""
    doc = build(evidence)
    results = doc.get("assessment-results", {}).get("results", [])
    if not results:
        return []
    return results[0].get("findings", [])


def to_json(evidence, indent=2):
    import json
    return json.dumps(build(evidence), indent=indent, sort_keys=True)
