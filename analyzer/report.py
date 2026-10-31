"""Turn the analysis into a Markdown report an analyst can paste into a ticket."""
from analyzer.ioc import defang
from analyzer.rules import mitre_techniques


def build_report(email_data, iocs, flags, total, rule_verdict, ai=None, ai_error=None):
    lines = [
        f"# Phishing triage: {email_data['subject']}",
        "",
        "## Verdict",
        "",
        f"- **Rule-based verdict:** {rule_verdict} (score {total})",
        f"- **MITRE ATT&CK:** {', '.join(mitre_techniques(flags)) or '-'}",
    ]

    if ai:
        lines += [
            f"- **AI verdict:** {ai.get('verdict', '?')} (confidence: {ai.get('confidence', '?')})",
            "",
            "## AI summary",
            "",
            ai.get("summary", ""),
            "",
            "**Recommended actions:**",
            "",
        ]
        lines += [f"- {action}" for action in ai.get("actions", [])]
    elif ai_error:
        lines += ["", f"_AI summary unavailable: {ai_error}_"]
    else:
        lines += ["", "_AI summary skipped (--no-ai)._"]

    lines += ["", "## Red flags", "", "| Severity | Check | Detail |", "|---|---|---|"]
    lines += [f"| {f['severity']} | {f['id']} | {f['detail']} |" for f in flags]
    if not flags:
        lines.append("| - | - | no red flags found |")

    lines += ["", "## Indicators of compromise (defanged)", ""]
    for kind in ("urls", "domains", "ips", "emails", "sha256"):
        values = iocs[kind] if kind == "sha256" else [defang(v) for v in iocs[kind]]
        if values:
            lines.append(f"**{kind}:**")
            lines += [f"- `{v}`" for v in values]
            lines.append("")

    auth = email_data["auth"]
    lines += [
        "## Headers",
        "",
        f"- From: {defang(email_data['from_address'])} ({email_data['from_name']})",
        f"- Reply-To: {defang(email_data['reply_to']) or '-'}",
        f"- Return-Path: {defang(email_data['return_path']) or '-'}",
        f"- Date: {email_data['date']}",
        f"- SPF: {auth['spf']} | DKIM: {auth['dkim']} | DMARC: {auth['dmarc']}",
        "",
    ]
    return "\n".join(lines)
