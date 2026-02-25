"""
Threat scoring engine – returns a score 0-100 with per-component breakdown.

Point budget
------------
Component                 Max pts
------------------------  -------
VT – sender IP              20
VT – sender domain          20
VT – attachment hash        20
AbuseIPDB – sender IP       20
Suspicious attachments      15
Shodan – sender IP           5
------------------------  -------
Total                      100
"""

from __future__ import annotations

from typing import Optional, Tuple


def _vt_pts(vt_result: Optional[dict], max_pts: int) -> Tuple[int, Optional[str]]:
    """Convert a VT result dict to (points, reason_or_None)."""
    if not isinstance(vt_result, dict) or "error" in vt_result:
        return 0, None
    s = vt_result.get("score", 0)
    if s > 15:
        return max_pts, f"score {s} (critical)"
    if s > 5:
        return int(max_pts * 0.75), f"score {s} (high)"
    if s > 0:
        return int(max_pts * 0.50), f"score {s} (medium)"
    return 0, None


def calculate_threat_score(analysis_data: dict, osint_data: dict) -> dict:
    score   = 0
    reasons: list[str] = []

    # ── 1. VT sender IP (max 20) ─────────────────────────────────────────────
    pts, reason = _vt_pts(osint_data.get("sender_ip_reputation"), 20)
    if pts:
        score += pts
        reasons.append(f"[VT-IP] {reason}")

    # ── 2. VT sender domain (max 20) ─────────────────────────────────────────
    pts, reason = _vt_pts(osint_data.get("sender_domain_reputation"), 20)
    if pts:
        score += pts
        reasons.append(f"[VT-Domain] {reason}")

    # ── 3. VT attachment hashes (max 20, worst single file counts) ────────────
    worst_pts, worst_reason = 0, None
    for name in analysis_data.get("attachments_hashes", {}):
        pts, reason = _vt_pts(osint_data.get(f"Hash reputation of {name} file"), 20)
        if pts > worst_pts:
            worst_pts    = pts
            worst_reason = f"[VT-Hash] {name}: {reason}"
    if worst_pts:
        score += worst_pts
        reasons.append(worst_reason)

    # ── 4. AbuseIPDB (max 20) ────────────────────────────────────────────────
    abuse = osint_data.get("confidence_of_abuse")
    if isinstance(abuse, dict) and "confidence" in abuse:
        c = abuse["confidence"]
        if c > 70:
            score += 20
            reasons.append(f"[AbuseIPDB] confidence {c}% (critical)")
        elif c > 30:
            score += 15
            reasons.append(f"[AbuseIPDB] confidence {c}% (high)")
        elif c > 0:
            score += 10
            reasons.append(f"[AbuseIPDB] confidence {c}% (medium)")

    # ── 5. Suspicious attachments (max 15) ───────────────────────────────────
    susp = analysis_data.get("suspicious_attachments", [])
    if len(susp) >= 2:
        score += 15
        names = ", ".join(a["name"] for a in susp)
        reasons.append(f"[Attachments] {len(susp)} suspicious files: {names}")
    elif len(susp) == 1:
        score += 10
        reasons.append(f"[Attachments] suspicious file: {susp[0]['name']} ({susp[0]['ext']})")

    # ── 6. Shodan (max 5) ────────────────────────────────────────────────────
    shodan = osint_data.get("shodan_ip")
    if isinstance(shodan, dict) and "error" not in shodan:
        tags         = {t.lower() for t in shodan.get("tags", [])}
        malicious    = {"malware", "c2", "botnet", "phishing", "scanner", "tor"}
        hit_tags     = malicious & tags
        vulns        = shodan.get("vulns", [])
        if hit_tags:
            score += 5
            reasons.append(f"[Shodan] malicious tags: {', '.join(sorted(hit_tags))}")
        elif vulns:
            score += 3
            reasons.append(f"[Shodan] {len(vulns)} CVE(s): {', '.join(vulns[:3])}")
        elif shodan.get("ports"):
            score += 2
            reasons.append(f"[Shodan] {len(shodan['ports'])} open port(s)")

    final = min(score, 100)

    if   final >= 70: level = "CRITICAL"
    elif final >= 40: level = "HIGH"
    elif final >= 20: level = "MEDIUM"
    elif final >   0: level = "LOW"
    else:             level = "CLEAN"

    return {"score": final, "level": level, "reasons": reasons}
