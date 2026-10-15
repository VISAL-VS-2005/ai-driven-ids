"""AI-powered PDF incident report generator.

Builds an attack report from the summary/alert JSON produced by converter.py,
uses the OpenRouter API (free models) for analysis + mitigations, and renders
a PDF with reportlab. Falls back to a built-in mitigation library when no API
key is supplied or the API call fails, so report generation always succeeds.
"""

import json
import os
import re
from datetime import datetime

import requests
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (HRFlowable, PageBreak, Paragraph, Preformatted,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

FREE_MODELS = [
    "google/gemma-4-31b-it:free",
    "google/gemma-4-26b-a4b-it:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "nvidia/nemotron-3.5-lightning:free",
    "thinkingmachines/inkling:free",
    "thinkingmachines/inkling-small:free",
    "poolside/laguna-s-2.1:free",
    "poolside/laguna-xs-2.1:free",
    "liquid/lfm-2.5-2.6b:free",
    "cohere/north-mini-code:free",
    "apodex/apodex-1.1-mini:free",
    "dots-studio/dots-3-note-preview:free",
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
    "nvidia/nemotron-3.5-content-safety:free",
]
DEFAULT_MODEL = FREE_MODELS[0]

# Built-in mitigations used as fallback and as baseline recommendations.
MITIGATIONS = {
    "Brute Force": [
        "Enforce multi-factor authentication on SSH/FTP and all remote login services.",
        "Rate-limit login attempts per source IP (e.g. fail2ban / sshguard) and lock accounts after repeated failures.",
        "Disable password authentication where key-based SSH authentication is sufficient.",
        "Restrict SSH/FTP access to management networks via firewall or VPN, and change default/non-standard ports only as a layer, not a control.",
        "Enable centralized authentication logging (SIEM) with alerting on login-failure bursts.",
    ],
    "Unauthorized Access": [
        "Block unauthorized access attempts at the perimeter firewall and internal ACLs.",
        "Verify the targeted service is required; shut down or bind it to localhost if not.",
        "Harden the exposed service (patch, disable anonymous/guest access, strong credentials).",
        "Deploy host-based IDS/IPS rules that alert on repeated connection attempts to the service.",
        "Review host logs for successful sessions from the offending source and isolate if compromised.",
    ],
    "Denial of Service": [
        "Enable SYN cookies / SYN proxy on the target host and tune tcp_max_syn_backlog.",
        "Deploy rate limiting on the edge (iptables/nftables connlimit, cloud anti-DDoS, upstream scrubbing).",
        "Use a reverse proxy or CDN to absorb flood traffic before it reaches origin servers.",
        "Tune IDS rules to reduce alert flooding while keeping detection of sustained floods.",
        "Have an incident-response runbook with bandwidth/scrubbing contacts for escalation.",
    ],
    "Reconnaissance": [
        "Block or rate-limit the scanning source at the firewall and drop unsolicited ICMP where policy allows.",
        "Harden the network surface: close unused ports, remove banner/version disclosure, disable unnecessary services.",
        "Keep vulnerability scans internal and schedule patching for exposed services.",
        "Correlate scan events with subsequent exploitation attempts; treat scanners as pre-attack indicators.",
        "Enable network-level anomaly detection to spot sweep patterns early.",
    ],
    "Web Attack": [
        "Deploy a WAF and enable SQL-injection virtual patching rules for the affected endpoint.",
        "Use parameterized queries / prepared statements - never concatenate user input into SQL.",
        "Apply least-privilege database accounts for the application (no DBA rights).",
        "Validate and encode all input server-side; reject payloads containing SQL metacharacters.",
        "Review application logs for successful injection attempts and check for data exfiltration.",
    ],
    "Malware": [
        "Isolate affected hosts from the network immediately.",
        "Run full antivirus/EDR scans and remove identified artifacts and persistence mechanisms.",
        "Block known C2 indicators at the DNS/firewall layer.",
        "Rotate credentials that may have been exposed.",
    ],
    "Exploitation": [
        "Apply vendor patches for the targeted service immediately.",
        "Restrict network exposure of the vulnerable service until patched.",
        "Hunt for indicators of compromise and validate no foothold was established.",
    ],
    "Other": [
        "Review the alert in context and correlate with adjacent events.",
        "Tune IDS rules to reduce noise and confirm detection coverage.",
        "Restrict suspicious sources at the firewall and monitor for escalation.",
    ],
}


class ReportError(Exception):
    pass


# --------------------------------------------------------------------------
# prompt / OpenRouter
# --------------------------------------------------------------------------

def build_digest(summary):
    """Compact JSON digest of everything the LLM needs for the analysis."""
    a = summary["attacks"]
    dig = {
        "total_alerts": summary["total_logs"],
        "time_range": summary["time_range"],
        "by_category": a["by_category"],
        "by_severity": a["by_severity"],
        "highest_severity": a["highest_severity"],
        "distinct_signatures": a["distinct_signatures"],
        "top_sources": summary["ips"]["top_sources"][:5],
        "top_targets": summary["ips"]["top_targets"][:5],
        "top_flows": summary["ips"]["top_flows"][:5],
        "unique_ips": summary["ips"]["unique_total"],
        "internal_ips": summary["ips"]["internal"],
        "top_dst_ports": summary["ports"]["top_dst_ports"][:8],
        "protocols": summary["protocols"],
        "peak_date": summary["timeline"]["peak_date"],
        "alerts_per_day": summary["timeline"]["by_date"],
        "attacks": [
            {k: d[k] for k in ("signature", "sid", "category", "severity", "count",
                               "percentage", "first_seen", "last_seen",
                               "top_sources", "top_targets", "top_dst_ports",
                               "protocols")}
            for d in summary["attack_details"]
        ],
    }
    return json.dumps(dig, indent=1, default=str)


def build_prompt(summary):
    digest = build_digest(summary)
    return f"""You are a senior cybersecurity analyst. Write the AI analysis section of an 
incident report based ONLY on the IDS alert data below (Snort/fast.log). 
Be specific: reference actual IPs, ports, counts and dates from the data.

Report data (JSON):
{digest}

Respond with plain Markdown ONLY (no code fences), using exactly these sections:

## Executive Summary
2-3 sentences describing what happened, the scale and the overall risk.

## Attack Analysis
For EACH attack category present in the data, a paragraph explaining what the 
attack is, what the observed traffic pattern indicates, and which asset is targeted.

## Risk Assessment
Bullets: business/technical impact of the observed activity, rated 
(Critical/High/Medium/Low) per category. Reference real numbers from the data.

## Recommended Mitigations
Concrete, actionable mitigations grouped by attack category (use **Category:** 
then bullets). Include firewall/IDS rule suggestions, host hardening and 
monitoring steps. At least 4 bullets per category present.

## Conclusion
2-3 sentences: current posture and priority actions.

Rules: factual, no filler, no disclaimers, Markdown only."""


def call_openrouter(prompt, api_key, model=None, timeout=90):
    """Call OpenRouter chat completions. Raises ReportError on failure."""
    model = model or DEFAULT_MODEL
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost",
        "X-Title": "IDS Attack Report",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system",
             "content": "You are a cybersecurity analyst writing incident report "
                        "sections in clean Markdown."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.4,
        "max_tokens": 3000,
    }
    try:
        resp = requests.post(OPENROUTER_URL, headers=headers, json=payload,
                             timeout=timeout)
    except requests.RequestException as exc:
        raise ReportError(f"network error calling OpenRouter: {exc}") from exc

    if resp.status_code == 401:
        raise ReportError("OpenRouter rejected the API key (401). Check the key.")
    if resp.status_code == 402:
        raise ReportError("OpenRouter credit/quota exhausted (402) for this key.")
    if resp.status_code >= 400:
        detail = resp.text[:300]
        raise ReportError(f"OpenRouter HTTP {resp.status_code}: {detail}")

    try:
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError) as exc:
        raise ReportError(f"unexpected OpenRouter response: {exc}") from exc
    if not content or not content.strip():
        raise ReportError("OpenRouter returned an empty response.")
    return content.strip(), model


def fallback_analysis(summary):
    """Deterministic analysis used when the LLM is unavailable."""
    lines = ["## Executive Summary", ""]
    a = summary["attacks"]
    top = a["by_signature"][0] if a["by_signature"] else None
    lines.append(
        f"The IDS recorded **{summary['total_logs']} alerts** across "
        f"**{a['distinct_signatures']} signatures** and **{a['distinct_categories']} "
        f"attack categories** between {summary['time_range']['start']} and "
        f"{summary['time_range']['end']}. The dominant activity is "
        f"**{top['signature']}** ({top['count']} alerts, {top['percentage']}%) "
        f"targeting {summary['ips']['top_targets'][0]['ip'] if summary['ips']['top_targets'] else 'N/A'}. "
        f"Overall risk level: **{str(a['highest_severity'] or 'medium').upper()}**."
    )
    lines += ["", "## Attack Analysis", ""]
    for d in summary["attack_details"]:
        srcs = ", ".join(s["ip"] for s in d["top_sources"][:3])
        tgts = ", ".join(f"{t['ip']}:{t['port']}" if t.get("port") else t["ip"]
                         for t in
                         [{"ip": x["ip"], "port": (d["top_dst_ports"][0]["port"]
                                                   if d["top_dst_ports"] else None)}
                          for x in d["top_targets"][:2]])
        lines.append(
            f"**{d['signature']}** ({d['category']}, severity {d['severity']}): "
            f"{d['count']} alerts ({d['percentage']}%) observed from {d['first_seen']} "
            f"to {d['last_seen']}. Primary sources: {srcs}. Primary targets: {tgts}. "
            f"Protocol(s): {', '.join(d['protocols'])}."
        )
        lines.append("")
    lines += ["## Risk Assessment", ""]
    for cat, cnt in a["by_category"].items():
        sev = next((d["severity"] for d in summary["attack_details"]
                    if d["category"] == cat), "medium")
        lines.append(f"- **{cat}** - {sev.upper()} - {cnt} alerts")
    lines += ["", "## Recommended Mitigations", ""]
    for cat in a["by_category"]:
        lines.append(f"**{cat}:**")
        for m in MITIGATIONS.get(cat, MITIGATIONS["Other"]):
            lines.append(f"- {m}")
        lines.append("")
    lines += ["## Conclusion", "",
              "Prioritize blocking the repeated access attempts and scanning sources, "
              "harden the targeted services, and confirm no successful sessions exist "
              "from the offending hosts. Continue monitoring for escalation from "
              "reconnaissance to exploitation."]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# markdown -> platypus
# --------------------------------------------------------------------------

def _escape(text):
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _inline(text):
    t = _escape(text)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"`([^`]+)`", r"<font face='Courier'>\1</font>", t)
    t = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<i>\1</i>", t)
    return t


def markdown_to_flowables(md, styles):
    """Very small Markdown subset -> Platypus flowables."""
    out = []
    lines = md.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        # markdown table
        if stripped.startswith("|") and stripped.endswith("|") and i + 1 < len(lines):
            rows_raw = []
            j = i
            while j < len(lines) and lines[j].strip().startswith("|"):
                rows_raw.append(lines[j].strip())
                j += 1
            rows = [[c.strip() for c in r.strip("|").split("|")] for r in rows_raw]
            rows = [r for r in rows
                    if not all(set(c) <= set("-: ") for c in r)]
            if rows:
                cols = max(len(r) for r in rows)
                rows = [r + [""] * (cols - len(r)) for r in rows]
                data = [[Paragraph(_inline(c), styles["TableCell"]) for c in r]
                        for r in rows]
                t = Table(data, repeatRows=1, colWidths=[170 / cols * mm] * cols)
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#94a3b8")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.white, colors.HexColor("#eef2f7")]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]))
                out.append(t)
                out.append(Spacer(1, 6))
            i = j
            continue

        m = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if m:
            level = len(m.group(1))
            style = {1: "H1", 2: "H2", 3: "H3"}.get(level, "H3")
            out.append(Paragraph(_inline(m.group(2)), styles[style]))
            out.append(Spacer(1, 4))
            i += 1
            continue

        if re.match(r"^(-{3,}|\*{3,}|_{3,})$", stripped):
            out.append(HRFlowable(width="100%", thickness=0.6,
                                  color=colors.HexColor("#94a3b8")))
            out.append(Spacer(1, 6))
            i += 1
            continue

        if re.match(r"^[-*+]\s+", stripped):
            items = []
            while i < len(lines) and re.match(r"^[-*+]\s+", lines[i].strip()):
                items.append(re.sub(r"^[-*+]\s+", "", lines[i].strip()))
                i += 1
            for it in items:
                out.append(Paragraph(f"\u2022&nbsp;&nbsp;{_inline(it)}",
                                     styles["Bullet"]))
            out.append(Spacer(1, 4))
            continue

        if re.match(r"^\d+[.)]\s+", stripped):
            items = []
            while i < len(lines) and re.match(r"^\d+[.)]\s+", lines[i].strip()):
                items.append(re.sub(r"^\d+[.)]\s+", "", lines[i].strip()))
                i += 1
            for n, it in enumerate(items, 1):
                out.append(Paragraph(f"{n}.&nbsp;&nbsp;{_inline(it)}", styles["Bullet"]))
            out.append(Spacer(1, 4))
            continue

        para = [stripped]
        i += 1
        while (i < len(lines) and lines[i].strip()
               and not re.match(r"^(#{1,4}\s|[-*+]\s|\d+[.)]\s|\|)", lines[i].strip())):
            para.append(lines[i].strip())
            i += 1
        out.append(Paragraph(_inline(" ".join(para)), styles["Body"]))
        out.append(Spacer(1, 5))
    return out


def _make_styles():
    base = getSampleStyleSheet()
    styles = {
        "Title": ParagraphStyle("RTitle", parent=base["Title"], fontSize=22,
                                leading=26, textColor=colors.HexColor("#0f172a"),
                                spaceAfter=4),
        "Subtitle": ParagraphStyle("RSub", parent=base["Normal"], fontSize=11,
                                   leading=14, alignment=TA_CENTER,
                                   textColor=colors.HexColor("#475569"),
                                   spaceAfter=14),
        "H1": ParagraphStyle("RH1", parent=base["Heading1"], fontSize=15,
                             leading=19, textColor=colors.HexColor("#1e3a5f"),
                             spaceBefore=14, spaceAfter=6),
        "H2": ParagraphStyle("RH2", parent=base["Heading2"], fontSize=12.5,
                             leading=16, textColor=colors.HexColor("#1e40af"),
                             spaceBefore=10, spaceAfter=4),
        "H3": ParagraphStyle("RH3", parent=base["Heading3"], fontSize=11,
                             leading=14, textColor=colors.HexColor("#334155"),
                             spaceBefore=8, spaceAfter=3),
        "Body": ParagraphStyle("RBody", parent=base["BodyText"], fontSize=9.5,
                               leading=13.5, alignment=TA_LEFT, spaceAfter=4),
        "Bullet": ParagraphStyle("RBul", parent=base["BodyText"], fontSize=9.5,
                                 leading=13.5, leftIndent=12, spaceAfter=2),
        "Cell": ParagraphStyle("RCell", parent=base["Normal"], fontSize=8.5,
                               leading=11),
        "TableCell": ParagraphStyle("RTCell", parent=base["Normal"], fontSize=8,
                                    leading=10.5),
        "Mono": ParagraphStyle("RMono", parent=base["Code"], fontSize=7,
                               leading=9, textColor=colors.HexColor("#334155")),
        "Caption": ParagraphStyle("RCap", parent=base["Normal"], fontSize=8,
                                  textColor=colors.HexColor("#64748b"),
                                  spaceBefore=2, spaceAfter=8),
    }
    return styles


def _table(data, col_widths, header=True, font_size=8.5):
    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#94a3b8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#eef2f7")]),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
                  ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    t.setStyle(TableStyle(style))
    return t


def _hdr_row(cells):
    return [Paragraph(f"<b>{c}</b>", ParagraphStyle(
        "th", fontSize=8.5, leading=11, textColor=colors.white)) for c in cells]


# --------------------------------------------------------------------------
# PDF assembly
# --------------------------------------------------------------------------

def build_pdf(summary, out_dir, ai_markdown=None, ai_meta=None):
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"attack_report_{stamp}.pdf")

    styles = _make_styles()
    story = []

    # ---- cover ----------------------------------------------------------
    story.append(Paragraph("IDS Intrusion Detection Report", styles["Title"]))
    story.append(Paragraph(
        f"Snort fast.log analysis &middot; source: "
        f"<b>{summary.get('source_file') or 'N/A'}</b> &middot; generated "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1.2,
                            color=colors.HexColor("#1f3a5f")))
    story.append(Spacer(1, 10))

    a = summary["attacks"]
    tr = summary["time_range"]
    meta = [
        ["Total alerts", str(summary["total_logs"]),
         "Attack signatures", str(a["distinct_signatures"])],
        ["Attack categories", str(a["distinct_categories"]),
         "Highest severity", str(a["highest_severity"] or "n/a").upper()],
        ["Unique IPs", str(summary["ips"]["unique_total"]),
         "Unique dst ports", str(summary["ports"]["unique_dst_ports"])],
        ["Time range start", str(tr["start"]), "Time range end", str(tr["end"])],
        ["Active days", str(tr["span_days"]), "Duration", str(tr["duration"])],
    ]
    story.append(_table([_hdr_row(["Metric", "Value", "Metric", "Value"])] + meta,
                        [38 * mm, 52 * mm, 38 * mm, 52 * mm]))
    story.append(Spacer(1, 8))

    # ---- attack breakdown table ----------------------------------------
    story.append(Paragraph("1. Attack Summary", styles["H1"]))
    rows = [_hdr_row(["Signature", "Category", "Severity", "Count", "%"])]
    for d in a["by_signature"]:
        rows.append([Paragraph(_inline(d["signature"]), styles["Cell"]),
                     Paragraph(d["category"], styles["Cell"]),
                     Paragraph(d["severity"].upper(), styles["Cell"]),
                     Paragraph(str(d["count"]), styles["Cell"]),
                     Paragraph(f"{d['percentage']}%", styles["Cell"])])
    story.append(_table(rows, [78 * mm, 34 * mm, 24 * mm, 17 * mm, 17 * mm]))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Alerts by category", styles["H2"]))
    rows = [_hdr_row(["Category", "Alerts", "Share"])]
    for cat, cnt in a["by_category"].items():
        share = round(cnt * 100.0 / summary["total_logs"], 2) if summary["total_logs"] else 0
        rows.append([cat, str(cnt), f"{share}%"])
    story.append(_table(rows, [90 * mm, 40 * mm, 40 * mm]))

    # ---- per-attack details --------------------------------------------
    story.append(Paragraph("2. Attack Details", styles["H1"]))
    for idx, d in enumerate(summary["attack_details"], 1):
        story.append(Paragraph(
            f"2.{idx} { _inline(d['signature']) }", styles["H2"]))
        rows = [
            _hdr_row(["Field", "Value"]),
            ["SID", f"{d['gid']}:{d['sid']}:{d['rev']}"],
            ["Category / Severity", f"{d['category']} / {d['severity'].upper()}"],
            ["Alert count", f"{d['count']} ({d['percentage']}% of all alerts)"],
            ["First seen", str(d["first_seen"])],
            ["Last seen", str(d["last_seen"])],
            ["Protocols", ", ".join(f"{k} ({v})" for k, v in d["protocols"].items())],
            ["Top sources", ", ".join(f"{s['ip']} ({s['count']})"
                                      for s in d["top_sources"]) or "-"],
            ["Top targets", ", ".join(f"{t['ip']} ({t['count']})"
                                      for t in d["top_targets"]) or "-"],
            ["Target ports", ", ".join(
                f"{p['port']}/{p['service'] or '?'} ({p['count']})"
                for p in d["top_dst_ports"]) or "-"],
        ]
        body = [rows[0]] + [[Paragraph(str(c), styles["Cell"]) for c in r]
                            for r in rows[1:]]
        story.append(_table(body, [45 * mm, 125 * mm]))
        if d["samples"]:
            story.append(Paragraph("Sample alerts:", styles["H3"]))
            for s in d["samples"][:5]:
                story.append(Preformatted(s, styles["Mono"]))
            story.append(Spacer(1, 6))

    # ---- network overview ----------------------------------------------
    story.append(Paragraph("3. Network Overview", styles["H1"]))
    story.append(Paragraph("Top source IPs", styles["H2"]))
    rows = [_hdr_row(["Source IP", "Alerts as source"])]
    for s in summary["ips"]["top_sources"]:
        rows.append([s["ip"], str(s["count"])])
    story.append(_table(rows, [85 * mm, 85 * mm]))

    story.append(Paragraph("Top targeted IPs", styles["H2"]))
    rows = [_hdr_row(["Target IP", "Alerts as target"])]
    for t in summary["ips"]["top_targets"]:
        rows.append([t["ip"], str(t["count"])])
    story.append(_table(rows, [85 * mm, 85 * mm]))

    story.append(Paragraph("Top targeted ports", styles["H2"]))
    rows = [_hdr_row(["Port", "Service", "Alerts"])]
    for p in summary["ports"]["top_dst_ports"]:
        rows.append([str(p["port"]), p["service"] or "-", str(p["count"])])
    story.append(_table(rows, [50 * mm, 70 * mm, 50 * mm]))

    story.append(Paragraph("Protocols", styles["H2"]))
    rows = [_hdr_row(["Protocol", "Alerts"])]
    for proto, cnt in summary["protocols"].items():
        rows.append([proto, str(cnt)])
    story.append(_table(rows, [85 * mm, 85 * mm]))

    # ---- timeline -------------------------------------------------------
    story.append(Paragraph("4. Timeline", styles["H1"]))
    rows = [_hdr_row(["Date", "Alerts"])]
    for d in summary["timeline"]["by_date"]:
        rows.append([d["date"], str(d["count"])])
    story.append(_table(rows, [85 * mm, 85 * mm]))
    story.append(Paragraph(
        f"Peak activity: {summary['timeline']['peak_date']} with "
        f"{summary['timeline']['peak_date_count']} alerts.",
        styles["Caption"]))

    # ---- AI analysis ----------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("5. AI Analysis & Recommended Mitigations", styles["H1"]))
    if ai_meta and ai_meta.get("used_ai"):
        story.append(Paragraph(
            f"Generated with <b>{ai_meta.get('model')}</b> via OpenRouter.",
            styles["Caption"]))
    else:
        reason = (ai_meta or {}).get("fallback_reason")
        story.append(Paragraph(
            f"Offline analysis (AI unavailable: {_escape(reason or 'not requested')}).",
            styles["Caption"]))
    md = ai_markdown or fallback_analysis(summary)
    story.extend(markdown_to_flowables(md, styles))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=0.8,
                            color=colors.HexColor("#94a3b8")))
    story.append(Paragraph(
        f"Report generated {datetime.now().isoformat(timespec='seconds')} from "
        f"{summary.get('source_file') or 'IDS alerts'} &middot; "
        f"{summary['total_logs']} alerts analysed.",
        styles["Caption"]))

    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(18 * mm, 10 * mm, "IDS Intrusion Detection Report")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title="IDS Intrusion Detection Report", author="IDS Dashboard")
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return path


def generate_report(summary, out_dir, api_key=None, model=None):
    """Full pipeline: optional AI analysis -> PDF.

    Returns (pdf_path, meta dict).
    """
    meta = {"used_ai": False, "model": None, "fallback_reason": None}
    md = None
    if api_key:
        try:
            prompt = build_prompt(summary)
            md, used_model = call_openrouter(prompt, api_key, model)
            meta.update(used_ai=True, model=used_model)
        except ReportError as exc:
            meta["fallback_reason"] = str(exc)
    else:
        meta["fallback_reason"] = "no API key provided"

    pdf_path = build_pdf(summary, out_dir, ai_markdown=md, ai_meta=meta)
    meta["pdf"] = pdf_path
    meta["size_bytes"] = os.path.getsize(pdf_path)
    return pdf_path, meta


if __name__ == "__main__":
    import sys
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    summary_file = sys.argv[1] if len(sys.argv) > 1 else "data/summary.json"
    key = os.environ.get("OPENROUTER_API_KEY")
    with open(summary_file, encoding="utf-8") as fh:
        s = json.load(fh)
    p, m = generate_report(s, "data/reports", api_key=key)
    print("pdf :", p)
    print("meta:", json.dumps({k: v for k, v in m.items() if k != "pdf"}, indent=2))
