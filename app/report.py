"""Markdown report generator for MailScope analysis results."""

from datetime import datetime, timezone
from pathlib import Path


def _badge(level: str) -> str:
    badges = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH":     "🟠 HIGH",
        "MEDIUM":   "🟡 MEDIUM",
        "LOW":      "🟢 LOW",
        "CLEAN":    "✅ CLEAN",
    }
    return badges.get(level, level)


def generate_markdown_report(
    analysis_data: dict,
    osint_data: dict,
    threat: dict,
    source_file: str,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    stem = Path(source_file).stem
    out_path = f"{stem}.eml_MailScope_Report.md"

    lines = []
    a = lines.append

    # ── Header ───────────────────────────────────────────────────────────────
    a("# MailScope Analysis Report")
    a("")
    a(f"**File:** `{source_file}`  ")
    a(f"**Generated:** {now}")
    a("")

    # ── Threat score ─────────────────────────────────────────────────────────
    score = threat.get("score", 0)
    level = threat.get("level", "CLEAN")
    a("---")
    a("")
    a("## Threat Score")
    a("")
    a(f"| Score | Level |")
    a(f"|-------|-------|")
    a(f"| **{score} / 100** | {_badge(level)} |")
    a("")

    reasons = threat.get("reasons", [])
    if reasons:
        a("### Score Breakdown")
        a("")
        for r in reasons:
            a(f"- {r}")
        a("")

    # ── Email metadata ────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## Email Metadata")
    a("")
    a(f"| Field | Value |")
    a(f"|-------|-------|")
    a(f"| **Subject** | {analysis_data.get('subject', 'N/A')} |")
    a(f"| **Date** | {analysis_data.get('date', 'N/A')} |")
    a(f"| **From** | {analysis_data.get('sender_addr', 'N/A')} |")
    a(f"| **Sender Domain** | {analysis_data.get('sender_domain', 'N/A')} |")
    a(f"| **Sender IP** | {analysis_data.get('sender_ip', 'N/A')} |")
    a(f"| **Return-Path** | {analysis_data.get('return_path', 'N/A')} |")
    a(f"| **Message-ID** | {analysis_data.get('message_id', 'N/A')} |")
    a(f"| **User-Agent/X-Mailer** | {analysis_data.get('user_agent', 'N/A')} |")
    recipients = analysis_data.get("recipients", [])
    a(f"| **Recipients** | {', '.join(recipients) if recipients else 'N/A'} |")
    a("")

    # ── Mail content ─────────────────────────────────────────────────────────
    content = (analysis_data.get("content") or "").strip()
    if content:
        a("### Mail Content")
        a("")
        a("```")
        a(content[:2000] + ("…" if len(content) > 2000 else ""))
        a("```")
        a("")

    # ── URLs ─────────────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## Extracted URLs")
    a("")
    urls = analysis_data.get("urls", [])
    if urls:
        for u in urls:
            a(f"- `{u}`")
    else:
        a("_No URLs found._")
    a("")

    # ── Attachments ──────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## Attachments")
    a("")
    hashes = analysis_data.get("attachments_hashes", {})
    susp_names = {s["name"] for s in analysis_data.get("suspicious_attachments", [])}

    if hashes:
        a("| File | SHA-256 | Alert |")
        a("|------|---------|-------|")
        for name, sha256 in hashes.items():
            alert = "⚠️ SUSPICIOUS EXTENSION" if name in susp_names else ""
            a(f"| `{name}` | `{sha256}` | {alert} |")
    else:
        a("_No attachments found._")
    a("")

    # ── VirusTotal ────────────────────────────────────────────────────────────
    if osint_data.get("vt_on"):
        a("---")
        a("")
        a("## VirusTotal")
        a("")

        ip_rep = osint_data.get("sender_ip_reputation")
        if isinstance(ip_rep, dict) and "error" not in ip_rep:
            flag = " ⚠️ HIGH RISK" if ip_rep.get("score", 0) > 10 else ""
            a(f"**Sender IP reputation:** {ip_rep.get('score', 0)}{flag}  ")
            a(f"Country: {ip_rep.get('country', 'N/A')} | ASN: {ip_rep.get('asn', 'N/A')} | AS Owner: {ip_rep.get('as_owner', 'N/A')}  ")
            a(f"VT Reputation: {ip_rep.get('reputation', 'N/A')}")
            a("")

        dom_rep = osint_data.get("sender_domain_reputation")
        if isinstance(dom_rep, dict) and "error" not in dom_rep:
            flag = " ⚠️ HIGH RISK" if dom_rep.get("score", 0) > 10 else ""
            a(f"**Sender domain reputation:** {dom_rep.get('score', 0)}{flag}  ")
            a(f"VT Reputation: {dom_rep.get('reputation', 'N/A')}")
            a("")

        for name in hashes:
            key = f"Hash reputation of {name} file"
            h_rep = osint_data.get(key)
            if isinstance(h_rep, dict) and "error" not in h_rep:
                flag = " ⚠️ HIGH RISK" if h_rep.get("score", 0) > 10 else ""
                a(f"**File `{name}` hash reputation:** {h_rep.get('score', 0)}{flag}  ")
                a(f"Type: {h_rep.get('type', 'N/A')} | Size: {h_rep.get('size', 'N/A')} bytes")
                a("")

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    if osint_data.get("abuse_on"):
        a("---")
        a("")
        a("## AbuseIPDB")
        a("")
        abuse = osint_data.get("confidence_of_abuse")
        if isinstance(abuse, dict) and "error" not in abuse:
            a(f"| Field | Value |")
            a(f"|-------|-------|")
            a(f"| Confidence of abuse | {abuse.get('confidence', 'N/A')}% |")
            a(f"| Reports (90 days) | {abuse.get('reports', 'N/A')} |")
            a(f"| Country | {abuse.get('country', 'N/A')} |")
            a(f"| ISP | {abuse.get('isp', 'N/A')} |")
            a(f"| Usage type | {abuse.get('usage', 'N/A')} |")
        else:
            a("_No AbuseIPDB data available._")
        a("")

    # ── Shodan ────────────────────────────────────────────────────────────────
    if osint_data.get("shodan_on"):
        a("---")
        a("")
        a("## Shodan")
        a("")
        shodan = osint_data.get("shodan_ip")
        if isinstance(shodan, dict) and "error" not in shodan:
            a(f"| Field | Value |")
            a(f"|-------|-------|")
            a(f"| Organization | {shodan.get('org', 'N/A')} |")
            a(f"| ISP | {shodan.get('isp', 'N/A')} |")
            a(f"| Country | {shodan.get('country', 'N/A')} |")
            ports = shodan.get("ports", [])
            a(f"| Open Ports | {', '.join(str(p) for p in ports) if ports else 'N/A'} |")
            tags = shodan.get("tags", [])
            a(f"| Tags | {', '.join(tags) if tags else 'N/A'} |")
            vulns = shodan.get("vulns", [])
            a(f"| CVEs | {', '.join(vulns) if vulns else 'None'} |")
            hostnames = shodan.get("hostnames", [])
            if hostnames:
                a(f"| Hostnames | {', '.join(hostnames)} |")
        else:
            a("_No Shodan data available._")
        a("")

    # ── URLScan ───────────────────────────────────────────────────────────────
    if osint_data.get("urlscan_on"):
        a("---")
        a("")
        a("## URLScan.io")
        a("")
        domain_scan = osint_data.get("sender_domain_scan")
        if isinstance(domain_scan, dict) and "result" in domain_scan:
            a(f"**Sender domain scan:** {domain_scan['result']}")
            a("")
        for u in urls:
            url_scan = osint_data.get(u)
            if isinstance(url_scan, dict) and "result" in url_scan:
                a(f"**URL** `{u}`: {url_scan['result']}")
        a("")

    # ── Footer ────────────────────────────────────────────────────────────────
    a("---")
    a("")
    a("_Report generated by [MailScope](https://github.com/WEX1000/MailScope)_")

    report_text = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return out_path
