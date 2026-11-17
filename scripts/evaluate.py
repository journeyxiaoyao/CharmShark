"""P0 regression + metrics harness.

Runs the engine over the synthetic fixtures and scores the result against the
expected per-scenario labels:

  * micro Precision / Recall / F1 over (scenario, category) pairs
  * false positives per hour of capture
  * evidence completeness (findings carrying frame numbers or flows)
  * TCP state sanity (a SYN sweep must not be classified as a failed connection)

Usage:
  python scripts/evaluate.py [--fixtures tests/fixtures/pcap] [--out reports]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# expected categories per fixture, and categories that must NOT appear
CASES = {
    "normal_modbus_polling": {
        "expect": {"CLEARTEXT_ENG", "NO_AUTH_OBSERVED"},
        "forbid": {"C2_BEACONING", "PERIODIC_COMMUNICATION", "C2_DNS_EXFIL"},
        "enrich": False,
    },
    "normal_dns_sync": {
        "expect": set(),
        "forbid": {"C2_BEACONING", "PERIODIC_COMMUNICATION", "C2_DNS_EXFIL",
                   "C2_DNS_TUNNEL_SUSPECT", "C2_DNS_HIGH_ENTROPY"},
        "enrich": False,
    },
    "attack_beacon_stable": {
        "expect": {"C2_BEACONING"},
        "forbid": set(),
        "enrich": False,
    },
    "attack_beacon_jitter": {
        "expect": {"C2_BEACONING"},
        "forbid": set(),
        "enrich": False,
    },
    "attack_syn_scan": {
        "expect": {"PORT_SCAN_TARGET"},
        "forbid": {"C2_BEACONING"},
        "enrich": False,
    },
    "attack_arp_poison": {
        "expect": {"ARP_DUPLICATE_IP_CLAIM", "ARP_GRATUITOUS_REPLY"},
        "forbid": {"C2_BEACONING"},
        "enrich": True,
    },
    "normal_ssdp": {
        "expect": set(),
        "forbid": {"C2_BEACONING", "PERIODIC_COMMUNICATION"},
        "enrich": False,
    },
    "normal_mdns": {
        "expect": set(),
        "forbid": {"C2_BEACONING", "PERIODIC_COMMUNICATION"},
        "enrich": False,
    },
    "normal_ftp_session": {
        "expect": {"CLEARTEXT_REMOTE_ACCESS"},
        "forbid": {"C2_BEACONING"},
        "enrich": False,
    },
    "probe_ftp_syn_only": {
        "expect": set(),
        "forbid": {"CLEARTEXT_REMOTE_ACCESS", "C2_BEACONING"},
        "enrich": False,
    },
}


def _run_engine(pcap: str, out_json: str, enrich: bool) -> bool:
    cmd = [
        sys.executable, "-m", "marlinspike",
        "--pcap", pcap, "--dpi-engine", "python",
        "-o", out_json,
    ]
    if not enrich:
        cmd.append("--no-enrich")
    cmd.append("chain")
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        print(f"  engine failed for {os.path.basename(pcap)}:\n{proc.stderr[-800:]}")
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default=os.path.join(ROOT, "tests", "fixtures", "pcap"))
    ap.add_argument("--out", default=os.path.join(ROOT, "reports"))
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    rows = []
    tp = fp = fn = 0
    total_findings = 0
    with_evidence = 0
    duration_s = 0.0

    for name, spec in CASES.items():
        pcap = os.path.join(args.fixtures, name + ".pcap")
        if not os.path.isfile(pcap):
            print(f"skip {name}: {pcap} missing")
            continue
        out_json = os.path.join(tempfile.gettempdir(), f"p0-eval-{name}.json")
        ok = _run_engine(pcap, out_json, spec["enrich"])
        if not ok:
            rows.append((name, "ENGINE ERROR", "", "", 0, 0, 0))
            continue
        with open(out_json, encoding="utf-8") as fh:
            report = json.load(fh)

        detected = {
            str(f.get("category", "")).upper()
            for f in report.get("risk_findings") or []
            if str(f.get("severity", "")).upper() != "INFO"
        }
        expected = spec["expect"]
        hit = detected & expected
        extra = detected - expected
        missed = expected - detected

        total_findings += len(report.get("risk_findings") or [])
        for f in report.get("risk_findings") or []:
            ev = f.get("evidence") or {}
            if ev.get("frame_numbers") or ev.get("flows"):
                with_evidence += 1

        try:
            duration_s += float((report.get("capture_info") or {}).get("duration_s") or 0)
        except (TypeError, ValueError):
            pass

        tp += len(hit)
        fp += len(extra)
        fn += len(missed)
        rows.append((
            name,
            "PASS" if not missed and not extra else "FAIL",
            ", ".join(sorted(hit)) or "-",
            ", ".join(sorted(extra)) or "-",
            len(hit), len(extra), len(missed),
        ))

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    hours = max(duration_s / 3600.0, 1e-9)
    fp_per_hour = fp / hours
    evidence_rate = (with_evidence / total_findings) if total_findings else 1.0

    lines = [
        "# P0 回归与指标评估",
        "",
        f"- 生成时间：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"- 场景数：{len(rows)}　总时长：{duration_s/60:.1f} 分钟　告警总数：{total_findings}",
        "",
        "## 逐场景结果",
        "",
        "| 场景 | 结论 | 命中 | 多余 | TP | FP | FN |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append("| " + " | ".join(str(x) for x in r) + " |")

    lines += [
        "",
        "## 指标",
        "",
        "| 指标 | 数值 |",
        "|---|---|",
        f"| Precision | {precision:.2%} |",
        f"| Recall | {recall:.2%} |",
        f"| F1 | {f1:.2%} |",
        f"| 每小时误报 | {fp_per_hour:.2f} |",
        f"| 证据完整率 | {evidence_rate:.2%} |",
        "",
        "> 说明：合成样本只用于回归与阈值校准，不能替代现场数据验收。",
    ]
    text = "\n".join(lines) + "\n"
    out_md = os.path.join(args.out, f"validation-{datetime.now():%Y%m%d-%H%M}.md")
    with open(out_md, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text)
    print(f"saved: {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
