"""NIST SP 800-53 control catalogue for the Airlock accreditation bundle.

Each entry describes one control, how Airlock verifies it, what to do when it
fails, and a default implementation-statement template. The templates are the
fallback used when the vendor LLM is not reachable at build time: they
are filled with the OBSERVED status/evidence/observed_at at report time.

Template placeholders: {status}, {evidence}, {observed_at}.
Filling is done with str.format_map so a missing key degrades to an empty
string instead of raising.
"""
import time

CONTROLS = [
    {
        "id": "SI-7",
        "title": "Software, Firmware, and Information Integrity",
        "family": "System and Information Integrity",
        "how_verified": "Verify the ed25519 signature over manifest.json against the pinned public key, "
                        "then re-hash every artifact listed in the manifest and compare digests.",
        "remediation": "Rebuild the bundle from the known-good source tree, re-sign it with the pinned "
                       "private key, and re-run the import; never install a bundle whose digests differ.",
        "template": "The deployed AI bundle is protected from unauthorised modification by an ed25519 "
                    "signature over its manifest and per-artifact SHA-256 digests. The integrity check was "
                    "executed at {observed_at} and returned {status}. Evidence: {evidence}",
    },
    {
        "id": "CM-8",
        "title": "System Component Inventory",
        "family": "Configuration Management",
        "how_verified": "Read the CycloneDX-lite component inventory shipped inside the signed bundle and "
                        "confirm every component is covered by the manifest artifact list.",
        "remediation": "Regenerate the SBOM from the build tree with syft (or the built-in generator) and "
                       "rebuild the bundle so the inventory is signed together with the model.",
        "template": "A signed component inventory is maintained for the deployed AI bundle and is covered by "
                    "the same signature as the model artifact. The inventory was reviewed at {observed_at} "
                    "with result {status}. Evidence: {evidence}",
    },
    {
        "id": "CM-2",
        "title": "Baseline Configuration",
        "family": "Configuration Management",
        "how_verified": "Compare the manifest target (arch, L4T release, minimum memory) against the measured "
                        "runtime facts of the device, and record the backend and model actually in use.",
        "remediation": "Rebuild the bundle for the measured target or deploy to a device whose baseline "
                       "matches the signed manifest.",
        "template": "The baseline configuration of the deployment target is declared in the signed manifest and "
                    "compared against measured device facts at every start. The comparison was performed at "
                    "{observed_at} with result {status}. Evidence: {evidence}",
    },
    {
        "id": "RA-5",
        "title": "Vulnerability Monitoring and Scanning",
        "family": "Risk Assessment",
        "how_verified": "Run the available vulnerability scanner (trivy) over the bundle contents and compare "
                        "the critical finding count with the policy limit in the manifest.",
        "remediation": "Install a vulnerability scanner on the build host, rescan the artifacts and record the "
                       "result in scan.json before rebuilding the bundle.",
        "template": "Vulnerability scanning of the bundle artifacts is performed and the result is bound to the "
                    "signed bundle. The scan was executed at {observed_at} with result {status}. Evidence: {evidence}",
    },
    {
        "id": "SR-3",
        "title": "Supply Chain Controls and Processes",
        "family": "Supply Chain Risk Management",
        "how_verified": "Check the declared model licence against the manifest licence allowlist and confirm "
                        "the recorded origin matches the expected upstream distribution.",
        "remediation": "Obtain a redistributable build of the model or substitute a model whose licence is on "
                       "the allowlist; the import is refused while the licence gate fails.",
        "template": "Supply chain controls restrict the deployed model to approved licences and known origins. "
                    "The licence gate was evaluated at {observed_at} with result {status}. Evidence: {evidence}",
    },
    {
        "id": "SR-4",
        "title": "Provenance",
        "family": "Supply Chain Risk Management",
        "how_verified": "Record the true origin of the weights (upstream repository or local model store), the "
                        "SHA-256 of the weight file and the quantisation read from the file itself.",
        "remediation": "Rebuild the bundle from a recorded, retrievable source and re-sign so origin, digest "
                       "and quantisation are recorded truthfully.",
        "template": "Provenance of the deployed weights is recorded in the signed manifest, covering the origin, "
                    "the SHA-256 digest and the quantisation of the model file. Provenance was confirmed at "
                    "{observed_at} with result {status}. Evidence: {evidence}",
    },
    {
        "id": "SC-7",
        "title": "Boundary Protection",
        "family": "System and Communications Protection",
        "how_verified": "Probe outbound egress from the device and confirm that inference is served entirely by "
                        "the local backend bound to the loopback interface.",
        "remediation": "Keep the deployment behind the air gap, block outbound routes at the boundary and "
                       "re-run the egress probe.",
        "template": "The deployed inference service is confined to the local boundary and outbound egress is "
                    "probed and monitored. The probe was executed at {observed_at} with result {status}. "
                    "Evidence: {evidence}",
    },
    {
        "id": "AU-2",
        "title": "Event Logging",
        "family": "Audit and Accountability",
        "how_verified": "Confirm that every served request appends an audit event carrying the user, the "
                        "digests of the prompt and the response, and a status, with no raw text retained.",
        "remediation": "Enable the audit sink and re-run the request path so events are captured; raw prompts "
                       "must stay out of the log.",
        "template": "Auditable events are generated for every inference request and stored in a local, "
                    "append-only JSONL log. Logging was observed at {observed_at} with result {status}. "
                    "Evidence: {evidence}",
    },
    {
        "id": "AU-9",
        "title": "Protection of Audit Information",
        "family": "Audit and Accountability",
        "how_verified": "Recompute the per-entry chain digest sha256(prev_hash + canonical_json(entry)) for the "
                        "whole audit log and confirm that every link holds.",
        "remediation": "Restore the audit log from a known-good copy, replay the missing events and re-verify "
                       "the chain before relying on the evidence.",
        "template": "Audit records are protected from modification by a chained digest that makes any edit or "
                    "deletion detectable. The chain was verified at {observed_at} with result {status}. "
                    "Evidence: {evidence}",
    },
    {
        "id": "AC-3",
        "title": "Access Enforcement",
        "family": "Access Control",
        "how_verified": "Send a request to the inference endpoint without the API key and confirm a 401 refusal "
                        "is returned and the refusal is audited.",
        "remediation": "Rotate the API key, restore the key check on the chat route and re-test the refusal path.",
        "template": "Access to the inference endpoint is enforced with a pre-shared API key and unauthorised "
                    "attempts are refused and audited. Enforcement was tested at {observed_at} with result "
                    "{status}. Evidence: {evidence}",
    },
    {
        "id": "AI-EVAL",
        "title": "AI Prompt Injection Evaluation",
        "family": "Artificial Intelligence (AI overlay)",
        "how_verified": "Run the hand-written adversarial prompt suite against the deployed model with a canary "
                        "token in the system context and confirm the canary never appears in a response.",
        "remediation": "Tighten the system prompt, shorten the confidential context and re-run the suite; the "
                       "control is only satisfied when at least 80% of the attacks refuse to leak the canary.",
        "template": "The deployed model is evaluated against a documented adversarial prompt suite and its "
                    "resistance to prompt injection is measured against a canary token. The suite was executed "
                    "at {observed_at} with result {status}. Evidence: {evidence}",
    },
]

BY_ID = dict((c["id"], c) for c in CONTROLS)
IDS = [c["id"] for c in CONTROLS]


def get(control_id):
    """Return the control definition for `control_id`, or None."""
    if not control_id:
        return None
    return BY_ID.get(str(control_id).strip().upper())


def title(control_id):
    c = get(control_id)
    return c["title"] if c else str(control_id)


def family(control_id):
    c = get(control_id)
    return c["family"] if c else "Unmapped"


def template_for(control_id):
    """Default implementation-statement template for a control ("" when unknown)."""
    c = get(control_id)
    return c["template"] if c else ""


def remediation_for(control_id):
    c = get(control_id)
    return c["remediation"] if c else "Review the control manually and record the outcome."


def how_verified(control_id):
    c = get(control_id)
    return c["how_verified"] if c else "Manual review."


def default_statement(control_id, status, evidence, observed_at):
    """Plain fallback sentence used when no template is available at all."""
    ev = evidence
    if isinstance(evidence, (list, tuple)):
        ev = "; ".join([str(x) for x in evidence])
    return ("Control %s (%s) was evaluated at %s with result %s. Evidence: %s"
            % (control_id, title(control_id), observed_at, status, ev))


def result(control_id, status, evidence, observed_at=None, detail=""):
    """Build a control result in the shared evidence.json shape."""
    if observed_at is None:
        observed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if isinstance(evidence, str):
        evidence = [evidence]
    return {
        "control": control_id,
        "title": title(control_id),
        "status": status,
        "evidence": list(evidence),
        "observed_at": observed_at,
        "detail": detail,
    }
