"""Snort fast.log converter.

Parses alert_fast.txt into structured JSON events and builds a summary log
used by the dashboard and the PDF report generator.

CLI:
    python3 converter.py                         # alert_fast.txt -> ./data/
    python3 converter.py path/to/alert_fast.txt out_dir
"""

import json
import os
import re
import socket
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

ALERT_RE = re.compile(
    r'^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})\s+\[\*\*\]\s+'
    r'\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
    r'"(?P<msg>[^"]+)"\s+\[\*\*\]\s+'
    r'\[Priority:\s*(?P<prio>\d+)\]\s+'
    r'\{(?P<proto>\w+)\}\s+'
    r'(?P<src>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<sport>\d+))?\s*->\s*'
    r'(?P<dst>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dport>\d+))?'
)

KNOWN_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 123: "ntp",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    8080: "http-alt", 8443: "https-alt", 5555: "ssh-alt",
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def service_name(port):
    if port is None:
        return None
    if port in KNOWN_SERVICES:
        return KNOWN_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def categorize(signature):
    """Map a Snort signature message to an attack category."""
    s = signature.lower()
    if "sql" in s and "inject" in s or "or 1=1" in s:
        return "Web Attack"
    if "ddos" in s or "syn flood" in s or re.search(r"\bflood\b", s):
        return "Denial of Service"
    if "brute" in s or "credential" in s or "password" in s:
        return "Brute Force"
    if "port scan" in s or "scan" in s or "sweep" in s or "recon" in s:
        return "Reconnaissance"
    if "icmp" in s or "ping" in s or "echo request" in s:
        return "Reconnaissance"
    if "ssh" in s or "ftp" in s or "telnet" in s or "rdp" in s:
        return "Unauthorized Access"
    if "malware" in s or "c2" in s or "beacon" in s:
        return "Malware"
    if "inject" in s or "xss" in s or "traversal" in s:
        return "Web Attack"
    if "exploit" in s or "overflow" in s or "cve-" in s:
        return "Exploitation"
    return "Other"


def severity_for(category, priority=None):
    table = {
        "Denial of Service": "critical",
        "Exploitation": "critical",
        "Web Attack": "critical",
        "Malware": "critical",
        "Brute Force": "high",
        "Unauthorized Access": "high",
        "Reconnaissance": "medium",
        "Other": "medium",
    }
    sev = table.get(category, "medium")
    # Snort priority: 1 = high, 2 = medium, 3 = low (0 means unset here)
    if priority in (1, 2, 3):
        by_prio = {1: "high", 2: "medium", 3: "low"}
        sev = by_prio[priority]
    return sev


def infer_year(month, day):
    """Snort fast.log has no year; assume a rolling 12-month window."""
    today = datetime.now()
    try:
        this_year = datetime(today.year, month, day)
    except ValueError:
        return today.year
    if this_year > today:
        return today.year - 1
    return today.year


def parse_line(line, line_no):
    line = line.rstrip("\n")
    if not line.strip():
        return None, None
    m = ALERT_RE.match(line)
    if not m:
        return None, line
    raw_ts = m.group("ts")
    month = int(raw_ts[0:2])
    day = int(raw_ts[3:5])
    year = infer_year(month, day)
    ts = datetime.strptime(f"{year}/{raw_ts}", "%Y/%m/%d-%H:%M:%S.%f")
    sig = m.group("msg")
    category = categorize(sig)
    priority = int(m.group("prio"))
    event = {
        "id": line_no,
        "timestamp": ts.isoformat(),
        "raw_timestamp": raw_ts,
        "gid": int(m.group("gid")),
        "sid": int(m.group("sid")),
        "rev": int(m.group("rev")),
        "signature": sig,
        "category": category,
        "severity": severity_for(category, priority),
        "priority": priority,
        "protocol": m.group("proto"),
        "src_ip": m.group("src"),
        "src_port": int(m.group("sport")) if m.group("sport") else None,
        "dst_ip": m.group("dst"),
        "dst_port": int(m.group("dport")) if m.group("dport") else None,
        "dst_service": service_name(int(m.group("dport"))) if m.group("dport") else None,
        "raw": line,
    }
    return event, None


def parse_file(path):
    events, errors = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            ev, err = parse_line(line, i)
            if ev:
                events.append(ev)
            elif err is not None:
                errors.append({"line_no": i, "line": err})
    return events, errors


def _count(items, key=None, limit=None):
    c = Counter(key(x) if key else x for x in items)
    out = [{"value": k, "count": v} for k, v in c.most_common(limit)]
    return out


def build_summary(events, source_file, parse_errors=None):
    total = len(events)
    parse_errors = parse_errors or []

    # --- attacks ---------------------------------------------------------
    sig_counter = Counter()
    sig_meta = {}
    for e in events:
        sig_counter[(e["sid"], e["signature"])] += 1
        sig_meta[(e["sid"], e["signature"])] = e

    by_signature = []
    for (sid, sig), cnt in sig_counter.most_common():
        e = sig_meta[(sid, sig)]
        by_signature.append({
            "sid": sid,
            "gid": e["gid"],
            "rev": e["rev"],
            "signature": sig,
            "category": e["category"],
            "severity": e["severity"],
            "count": cnt,
            "percentage": round(cnt * 100.0 / total, 2) if total else 0.0,
        })

    by_category = dict(Counter(e["category"] for e in events).most_common())
    by_severity = dict(Counter(e["severity"] for e in events).most_common())
    by_severity = dict(sorted(by_severity.items(),
                              key=lambda kv: -SEVERITY_RANK.get(kv[0], 0)))
    by_priority = dict(Counter(f"P{e['priority']}" for e in events).most_common())

    # --- ips -------------------------------------------------------------
    src_counts = Counter(e["src_ip"] for e in events)
    dst_counts = Counter(e["dst_ip"] for e in events)
    all_ips = set(src_counts) | set(dst_counts)
    flows = Counter((e["src_ip"], e["dst_ip"]) for e in events)

    def is_internal(ip):
        return ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                              "172.19.", "172.2", "172.30.", "172.31."))

    ips = {
        "unique_total": len(all_ips),
        "unique_sources": len(src_counts),
        "unique_destinations": len(dst_counts),
        "internal": sorted(ip for ip in all_ips if is_internal(ip)),
        "external": sorted(ip for ip in all_ips if not is_internal(ip)),
        "top_sources": [{"ip": ip, "count": c} for ip, c in src_counts.most_common(10)],
        "top_targets": [{"ip": ip, "count": c} for ip, c in dst_counts.most_common(10)],
        "top_flows": [{"src_ip": s, "dst_ip": d, "count": c}
                      for (s, d), c in flows.most_common(10)],
        "per_ip": [{"ip": ip,
                    "as_source": src_counts.get(ip, 0),
                    "as_target": dst_counts.get(ip, 0),
                    "total": src_counts.get(ip, 0) + dst_counts.get(ip, 0)}
                   for ip in sorted(all_ips,
                                    key=lambda x: -(src_counts.get(x, 0) + dst_counts.get(x, 0)))],
    }

    # --- ports -----------------------------------------------------------
    dst_ports = Counter(e["dst_port"] for e in events if e["dst_port"] is not None)
    src_ports = Counter(e["src_port"] for e in events if e["src_port"] is not None)
    ports = {
        "unique_dst_ports": len(dst_ports),
        "unique_src_ports": len(src_ports),
        "top_dst_ports": [{"port": p, "service": service_name(p), "count": c}
                          for p, c in dst_ports.most_common(10)],
        "top_src_ports": [{"port": p, "count": c} for p, c in src_ports.most_common(10)],
    }

    # --- protocols -------------------------------------------------------
    protocols = dict(Counter(e["protocol"] for e in events).most_common())

    # --- timeline --------------------------------------------------------
    by_date = Counter(e["timestamp"][:10] for e in events)
    by_hour = Counter(e["timestamp"][11:13] + ":00" for e in events)
    # alerts per day (ordered)
    dates_sorted = sorted(by_date)
    peak_date = dates_sorted[0] if dates_sorted else None
    if peak_date and by_date:
        peak_date = max(by_date, key=by_date.get)

    timestamps = sorted(e["timestamp"] for e in events)
    time_range = {
        "start": timestamps[0] if timestamps else None,
        "end": timestamps[-1] if timestamps else None,
        "days": dates_sorted,
        "span_days": len(dates_sorted),
    }
    if timestamps:
        t0 = datetime.fromisoformat(timestamps[0])
        t1 = datetime.fromisoformat(timestamps[-1])
        delta = t1 - t0
        time_range["duration"] = str(delta).split(".")[0]
    else:
        time_range["duration"] = "0:00:00"

    timeline = {
        "by_date": [{"date": d, "count": by_date[d]} for d in dates_sorted],
        "by_hour": [{"hour": h, "count": by_hour[h]} for h in sorted(by_hour)],
        "peak_date": peak_date,
        "peak_date_count": by_date.get(peak_date, 0) if peak_date else 0,
    }

    # --- per-signature detail (attack details for the report) -------------
    attack_details = []
    for entry in by_signature:
        subset = [e for e in events if e["sid"] == entry["sid"]]
        s_src = Counter(e["src_ip"] for e in subset)
        s_dst = Counter(e["dst_ip"] for e in subset)
        s_dport = Counter(e["dst_port"] for e in subset if e["dst_port"] is not None)
        sub_ts = sorted(e["timestamp"] for e in subset)
        attack_details.append({
            **entry,
            "first_seen": sub_ts[0] if sub_ts else None,
            "last_seen": sub_ts[-1] if sub_ts else None,
            "protocols": dict(Counter(e["protocol"] for e in subset).most_common()),
            "top_sources": [{"ip": ip, "count": c} for ip, c in s_src.most_common(5)],
            "top_targets": [{"ip": ip, "count": c} for ip, c in s_dst.most_common(5)],
            "top_dst_ports": [{"port": p, "service": service_name(p), "count": c}
                              for p, c in s_dport.most_common(5)],
            "samples": [e["raw"] for e in subset[:5]],
        })

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_file": os.path.basename(source_file) if source_file else None,
        "total_logs": total,
        "parse_errors": len(parse_errors),
        "time_range": time_range,
        "attacks": {
            "total_alerts": total,
            "distinct_signatures": len(by_signature),
            "distinct_categories": len(by_category),
            "by_signature": by_signature,
            "by_category": by_category,
            "by_severity": by_severity,
            "by_priority": by_priority,
            "highest_severity": next((s for s in ("critical", "high", "medium", "low", "info")
                                      if by_severity.get(s)), None),
        },
        "ips": ips,
        "ports": ports,
        "protocols": protocols,
        "timeline": timeline,
        "attack_details": attack_details,
    }


def write_outputs(events, out_dir, source_file, parse_errors=None):
    os.makedirs(out_dir, exist_ok=True)
    alerts_path = os.path.join(out_dir, "alerts.json")
    summary_path = os.path.join(out_dir, "summary.json")
    with open(alerts_path, "w", encoding="utf-8") as fh:
        json.dump({
            "source_file": os.path.basename(source_file) if source_file else None,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "count": len(events),
            "events": events,
        }, fh, indent=2)
    summary = build_summary(events, source_file, parse_errors)
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    return alerts_path, summary_path, summary


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    src = argv[0] if argv else "alert_fast.txt"
    out_dir = argv[1] if len(argv) > 1 else "data"
    if not os.path.exists(src):
        print(f"error: {src} not found", file=sys.stderr)
        return 1
    events, errors = parse_file(src)
    alerts_path, summary_path, summary = write_outputs(events, out_dir, src, errors)
    a = summary["attacks"]
    print(f"parsed   : {summary['total_logs']} alerts ({summary['parse_errors']} bad lines)")
    print(f"alerts   : {alerts_path}")
    print(f"summary  : {summary_path}")
    print(f"signatures: {a['distinct_signatures']}  categories: {a['distinct_categories']}")
    print(f"ips      : {summary['ips']['unique_total']} unique")
    print(f"ports    : {summary['ports']['unique_dst_ports']} unique destination ports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
