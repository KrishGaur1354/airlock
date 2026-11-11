"""Accreditation reporting: POA&M items, System Security Plan (SSP) and POA&M HTML.

Everything here is stdlib only and self-contained: the generated HTML embeds its
own CSS and never references a CDN, so it can be opened on an air-gapped device.

    poam_items(evidence, today=None) -> [POA&M]
    render_ssp(evidence, statements=None) -> str (HTML)
    render_poam(items) -> str (HTML)

Implementation statements may be supplied per control. A missing statement falls
back to the catalogue template in airlock.controls, and a missing catalogue
template falls back to a plain default sentence. Templates are filled with the
OBSERVED status/evidence/observed_at using str.format_map over a safe mapping,
so unknown placeholders never raise.
"""
import datetime
import html
import os
import sys

if __package__ in (None, ""):  # pragma: no cover - direct execution fallback
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from airlock import controls
else:
    from airlock import controls

DAYS_TO_MILESTONE = 30
STATUS_LABEL = {"pass": "Satisfied", "fail": "Not Satisfied", "unknown": "Unknown"}


class _SafeDict(dict):
    """Mapping for str.format_map: unknown keys render as an empty string."""

    def __missing__(self, key):
        return ""


# ------------------------------------------------------------------ helpers
def _as_date(today=None):
    if today is None:
        return datetime.date.today()
    if isinstance(today, datetime.datetime):
        return today.date()
    if isinstance(today, datetime.date):
        return today
    if isinstance(today, str):
        try:
            return datetime.datetime.strptime(today.strip(), "%Y-%m-%d").date()
        except ValueError:
            return datetime.date.today()
    return datetime.date.today()


def _text(value):
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "; ".join([str(v) for v in value])
    return str(value)


def _fill(template, status, evidence, observed_at):
    """Fill a statement template with observed values; never raises."""
    if not template:
        return ""
    safe = _SafeDict({"status": _text(status), "evidence": _text(evidence),
                      "observed_at": _text(observed_at)})
    try:
        return template.format_map(safe)
    except (ValueError, IndexError, KeyError, TypeError):
        return str(template)


def _statement_text(statement):
    """Accept a plain template string or a dict describing one."""
    if statement is None:
        return ""
    if isinstance(statement, dict):
        for key in ("statement", "implementation_statement", "text", "template"):
            if key in statement:
                return _statement_text(statement[key])
        return ""
    return str(statement)


def statements_from_controls(controls_json):
    """Extract {control_id: statement_template} from a bundle controls.json blob."""
    out = {}
    if isinstance(controls_json, dict):
        items = controls_json.get("controls", controls_json)
        if isinstance(items, dict):
            items = [dict(v, id=k) for k, v in items.items() if isinstance(v, dict)]
        if isinstance(items, list):
            for c in items:
                if not isinstance(c, dict):
                    continue
                cid = c.get("control") or c.get("id")
                if not cid:
                    continue
                out[str(cid)] = _statement_text(c.get("template") or c.get("statement"))
    return out


def _control_rows(evidence, statements=None):
    """Return [(control_result, statement_text)] for every control in the evidence."""
    statements = statements or {}
    if isinstance(statements, dict) and "controls" in statements:
        # the whole controls.json blob shipped inside the bundle was passed in
        statements = statements_from_controls(statements)
    rows = []
    for c in (evidence or {}).get("controls", []):
        if not isinstance(c, dict):
            continue
        cid = c.get("control", "")
        tpl = _statement_text(statements.get(cid))
        if not tpl:
            tpl = controls.template_for(cid)
        if not tpl:
            tpl = controls.default_statement(cid, c.get("status"), c.get("evidence"),
                                             c.get("observed_at"))
        statement = _fill(tpl, c.get("status"), c.get("evidence"), c.get("observed_at"))
        rows.append((c, statement))
    return rows


# ------------------------------------------------------------------ POA&M
def poam_items(evidence, today=None):
    """Build one POA&M item per unsatisfied (fail) or unknown control."""
    base = _as_date(today)
    milestone = (base + datetime.timedelta(days=DAYS_TO_MILESTONE)).isoformat()
    items = []
    n = 0
    for c in (evidence or {}).get("controls", []):
        if not isinstance(c, dict):
            continue
        status = c.get("status")
        if status == "pass":
            continue
        n += 1
        cid = c.get("control", "")
        detail = _text(c.get("detail"))
        evidence_text = _text(c.get("evidence"))
        if status == "unknown":
            weakness = ("Unable to demonstrate control %s (%s) on the deployed system."
                        % (cid, controls.title(cid)))
        else:
            weakness = ("Control %s (%s) is not satisfied on the deployed system."
                        % (cid, controls.title(cid)))
        if detail:
            weakness += " " + detail
        if evidence_text:
            weakness += " Observed: " + evidence_text
        items.append({
            "id": "POAM-%03d" % n,
            "control": cid,
            "weakness": weakness,
            "remediation": controls.remediation_for(cid),
            "milestone_date": milestone,
            "status": "open",
        })
    return items


# ------------------------------------------------------------------ HTML
_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin: 0; padding: 32px; background: #f5f6f8; color: #16181d; line-height: 1.45; }
h1 { font-size: 24px; margin: 0 0 4px; letter-spacing: -0.2px; }
h2 { font-size: 16px; margin: 28px 0 10px; text-transform: uppercase; letter-spacing: 1px;
     color: #5b6270; }
.sub { color: #5b6270; margin: 0 0 22px; font-size: 13px; }
.card { background: #fff; border: 1px solid #e2e5ea; border-radius: 10px; padding: 18px 20px; margin-bottom: 18px; }
table { width: 100%; border-collapse: collapse; background: #fff; font-size: 13px;
        border: 1px solid #e2e5ea; border-radius: 10px; overflow: hidden; }
th { text-align: left; background: #eef0f4; padding: 9px 12px; font-size: 11px; text-transform: uppercase;
     letter-spacing: 0.8px; color: #4b5260; border-bottom: 1px solid #e2e5ea; }
td { padding: 10px 12px; border-bottom: 1px solid #eef0f4; vertical-align: top; }
tr:last-child td { border-bottom: none; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.pill { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600;
        letter-spacing: 0.4px; white-space: nowrap; }
.pass { background: #dcf5e5; color: #14663a; }
.fail { background: #fde0e0; color: #9b1c1c; }
.unknown { background: #fdf0d5; color: #8a5a06; }
.kv { display: grid; grid-template-columns: 210px 1fr; gap: 6px 18px; font-size: 13px; }
.kv dt { color: #6b7280; }
.kv dd { margin: 0; }
footer { margin-top: 26px; color: #8a909c; font-size: 11px; }
@media print { body { background: #fff; padding: 0; } .card, table { break-inside: avoid; } }
"""


def _doc(title, body):
    return ("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            "<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n%s\n"
            "<footer>Generated by Airlock - OSCAL-shaped accreditation evidence. "
            "Self-contained document, no external references.</footer>\n</body>\n</html>\n"
            % (html.escape(title), _CSS, body))


def _status_pill(status):
    cls = status if status in ("pass", "fail", "unknown") else "unknown"
    return "<span class=\"pill %s\">%s</span>" % (cls, html.escape(STATUS_LABEL.get(status, str(status))))


def _e(value):
    return html.escape(_text(value))


def render_ssp(evidence, statements=None):
    """Render the System Security Plan as a self-contained HTML document."""
    evidence = evidence or {}
    bundle = evidence.get("bundle", {}) or {}
    device = evidence.get("device", {}) or {}
    summary = evidence.get("summary", {}) or {}
    audit = evidence.get("audit", {}) or {}
    target = bundle.get("target", {}) or {}
    rows = _control_rows(evidence, statements)

    total = summary.get("total", len(rows))
    satisfied = summary.get("satisfied", len([r for r, _ in rows if r.get("status") == "pass"]))

    out = []
    out.append("<h1>System Security Plan (SSP)</h1>")
    out.append("<p class=\"sub\">Airlock signed offline AI bundle - generated %s</p>"
               % _e(evidence.get("generated", "")))

    out.append("<div class=\"card\"><dl class=\"kv\">")
    for label, value in (
            ("System / bundle", "%s v%s" % (bundle.get("name", "-"), bundle.get("version", "-"))),
            ("Signer fingerprint", bundle.get("signer_fingerprint", "-")),
            ("Target", "%s / %s / %s" % (target.get("device", "-"), target.get("arch", "-"),
                                         target.get("l4t_release", "-"))),
            ("Device", "%s / %s / %s MB RAM" % (device.get("backend", "-"), device.get("model", "-"),
                                               device.get("ram_mb", "-"))),
            ("Controls satisfied", "%s of %s" % (satisfied, total)),
            ("Audit chain", "%s (%s entries)" % ("verified" if audit.get("ok") else "BROKEN",
                                                audit.get("entries", 0))),
    ):
        out.append("<dt>%s</dt><dd>%s</dd>" % (_e(label), _e(value)))
    out.append("</dl></div>")

    out.append("<h2>Control implementation statements</h2>")
    out.append("<table><thead><tr><th>Control</th><th>Title</th><th>Status</th>"
               "<th>Implementation statement</th><th>Observed evidence</th><th>Observed at</th>"
               "</tr></thead><tbody>")
    for c, statement in rows:
        ev = c.get("evidence", [])
        if isinstance(ev, (list, tuple)):
            ev_text = "<br>".join([_e(x) for x in ev])
        else:
            ev_text = _e(ev)
        out.append("<tr><td class=\"mono\">%s</td><td>%s</td><td>%s</td><td>%s</td>"
                   "<td>%s</td><td class=\"mono\">%s</td></tr>"
                   % (_e(c.get("control", "")), _e(c.get("title", "")), _status_pill(c.get("status", "unknown")),
                      statement, ev_text, _e(c.get("observed_at", ""))))
    out.append("</tbody></table>")
    return _doc("System Security Plan - %s" % bundle.get("name", "Airlock"), "\n".join(out))


def render_poam(items, title="Plan of Action and Milestones (POA&M)"):
    """Render POA&M items as a self-contained HTML document."""
    items = items or []
    out = []
    out.append("<h1>%s</h1>" % html.escape(title))
    out.append("<p class=\"sub\">%d open item(s) - milestone date is 30 days from assessment</p>"
               % len(items))
    if not items:
        out.append("<div class=\"card\">No open findings: every assessed control is satisfied.</div>")
        return _doc(title, "\n".join(out))
    out.append("<table><thead><tr><th>ID</th><th>Control</th><th>Weakness</th><th>Remediation</th>"
               "<th>Milestone</th><th>Status</th></tr></thead><tbody>")
    for it in items:
        out.append("<tr><td class=\"mono\">%s</td><td class=\"mono\">%s</td><td>%s</td><td>%s</td>"
                   "<td class=\"mono\">%s</td><td><span class=\"pill fail\">%s</span></td></tr>"
                   % (_e(it.get("id", "")), _e(it.get("control", "")), _e(it.get("weakness", "")),
                      _e(it.get("remediation", "")), _e(it.get("milestone_date", "")),
                      _e(it.get("status", "open"))))
    out.append("</tbody></table>")
    return _doc(title, "\n".join(out))
