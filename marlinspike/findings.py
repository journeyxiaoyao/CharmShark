"""P0 evidence-chain helpers for ``RiskFinding``.

Additive-only design: every helper tolerates both ``RiskFinding`` dataclass
instances (engine time) and plain dicts (post-serialization, plugin merge,
old reports loaded from disk). Nothing here removes or renames an existing
field, so older report files keep rendering.

Semantics (see the design doc, §4.2/§4.3):

* ``observation_status`` — where the fact comes from:
  OBSERVED (seen in traffic) / INFERRED (rule or statistic) /
  CONFIGURED (site configuration) / UNKNOWN.
* ``capture_visibility`` — COMPLETE / PARTIAL / UNKNOWN. Used so a one-way
  capture is never reported as a confirmed fact.
* ``evidence_quality`` — LOW / MEDIUM / HIGH, derived from whether the finding
  carries frame numbers, flow records, and protocol fields.
"""

from __future__ import annotations

# ── enum-like constants ────────────────────────────────────────────────────
OBSERVED = "OBSERVED"
INFERRED = "INFERRED"
CONFIGURED = "CONFIGURED"
UNKNOWN = "UNKNOWN"

VIS_COMPLETE = "COMPLETE"
VIS_PARTIAL = "PARTIAL"
VIS_UNKNOWN = "UNKNOWN"

QUALITY_LOW = "LOW"
QUALITY_MEDIUM = "MEDIUM"
QUALITY_HIGH = "HIGH"

RULE_VERSION = "1.0"

#: Default confidence by observation status. Rules may override per finding;
#: these are conservative baselines, not calibrated probabilities.
DEFAULT_CONFIDENCE = {
    OBSERVED: 0.9,
    INFERRED: 0.6,
    CONFIGURED: 1.0,
    UNKNOWN: 0.3,
}

#: Categories whose evidence is a direct observation in the capture.
OBSERVED_CATEGORIES = {
    "MODBUS_WRITE_ANON",
    "S7_PROGRAM_ACCESS",
    "OPC_NO_SECURITY",
    "CLEARTEXT_ENG",
    "CLEARTEXT_REMOTE_ACCESS",
    "ICS_EXTERNAL_COMMS",
    "CROSS_PURDUE",
    "EXTERNAL_IPS_OBSERVED",
    "MALWARE_IOC_MATCH",
    "UNKNOWN_SERVICE_PORT",
    "HIGH_PORT_SERVICE",
    "PORT_SCAN_TARGET",
    "ARP_DUPLICATE_IP_CLAIM",
    "ARP_GATEWAY_MAC_CHANGE",
    "ARP_GRATUITOUS_REPLY",
    "ARP_SCAN_BEHAVIOR",
    "ARP_BROADCAST_STORM",
    "ARP_MAC_CLAIMS_MANY_IPS",
}

#: Categories driven by statistics or by the *absence* of an expected signal.
INFERRED_CATEGORIES = {
    "C2_BEACONING",
    "C2_PERSISTENCE",
    "C2_DATA_EXFIL",
    "C2_DNS_EXFIL",
    "C2_DNS_TUNNEL_SUSPECT",
    "C2_DNS_HIGH_ENTROPY",
    "C2_SUSPECT_CHANNEL",
    "PERIODIC_COMMUNICATION",
    "SUSPECTED_C2_BEACON",
    "NO_AUTH_OBSERVED",
    "IT_SERVICE_ON_OT_DEVICE",
    "APT_C2_BEACON",
    "APT_LATERAL_MOVEMENT_SMB",
    "APT_LATERAL_MOVEMENT_RDP",
    "APT_LATERAL_MOVEMENT_WINRM",
    "APT_OT_RECONNAISSANCE",
    "APT_NEW_HOST_PROTOCOL",
}

#: Default limitation text attached to inferred findings, so the report never
#: presents a statistical conclusion as a confirmed fact.
DEFAULT_LIMITATIONS = {
    INFERRED: "基于被动流量的统计/推断结论，未做主动验证。",
    OBSERVED: "直接观察自抓包，但仅覆盖采集窗口内的可见流量。",
    CONFIGURED: "结论来自站点配置，未与实时流量核对。",
    UNKNOWN: "证据不足，需人工复核。",
}


# ── dict / object access helpers ───────────────────────────────────────────
def _get(f, key, default=None):
    if isinstance(f, dict):
        return f.get(key, default)
    return getattr(f, key, default)


def _set(f, key, value):
    if isinstance(f, dict):
        f[key] = value
    else:
        setattr(f, key, value)


def _truthy(value) -> bool:
    return bool(value) if value not in (None, "", [], {}) else False


# ── builders ───────────────────────────────────────────────────────────────
def new_finding_id(category: str, seq: int) -> str:
    """Stable, readable id: ``finding-<category slug>-<seq>``."""
    slug = (category or "finding").strip().lower().replace("_", "-") or "finding"
    return f"finding-{slug}-{seq:03d}"


def empty_evidence(visibility: str = VIS_UNKNOWN) -> dict:
    return {
        "frame_numbers": [],
        "flows": [],
        "protocol_fields": [],
        "feature_values": {},
        "capture_visibility": visibility,
    }


def empty_detection(method: str = "rule") -> dict:
    return {"method": method, "matched_conditions": [], "limitations": []}


def _evidence_quality(evidence: dict) -> str:
    frames = evidence.get("frame_numbers") or []
    flows = evidence.get("flows") or []
    fields = evidence.get("protocol_fields") or []
    if frames and flows:
        return QUALITY_HIGH
    if frames or flows or fields:
        return QUALITY_MEDIUM
    return QUALITY_LOW


def _default_status(category: str) -> str:
    cat = str(category or "").upper()
    if cat in OBSERVED_CATEGORIES:
        return OBSERVED
    if cat in INFERRED_CATEGORIES:
        return INFERRED
    return INFERRED


def attach_flow_evidence(findings, flows, max_flows: int = 20, max_frames: int = 50) -> None:
    """Link findings to flow records / frame numbers by endpoint match.

    P0 keeps this deliberately simple: a finding is linked to the flows that
    touch one of its ``affected_nodes``. That is enough to let an analyst jump
    from a finding back to the capture; precise per-rule linkage comes later.
    """
    if not flows:
        return
    for f in findings or []:
        nodes = {str(x) for x in (_get(f, "affected_nodes") or []) if x}
        if not nodes:
            continue
        ev = _get(f, "evidence") or {}
        if not isinstance(ev, dict):
            ev = {}
        if ev.get("flows"):
            continue
        matched = []
        for flow in flows:
            if flow.get("src_ip") in nodes or flow.get("dst_ip") in nodes:
                matched.append(flow)
                if len(matched) >= max_flows:
                    break
        if not matched:
            continue
        frames = []
        for flow in matched:
            for fn in flow.get("frame_numbers") or []:
                if fn not in frames:
                    frames.append(fn)
                if len(frames) >= max_frames:
                    break
            if len(frames) >= max_frames:
                break
        ev.setdefault("frame_numbers", [])
        ev.setdefault("protocol_fields", [])
        ev.setdefault("feature_values", {})
        ev["flows"] = [
            {
                "flow_id": fl.get("flow_id"),
                "src_ip": fl.get("src_ip"),
                "src_port": fl.get("src_port"),
                "dst_ip": fl.get("dst_ip"),
                "dst_port": fl.get("dst_port"),
                "transport": fl.get("transport"),
                "tcp_state": fl.get("tcp_state"),
                "visibility": fl.get("visibility"),
                "packets": fl.get("packets"),
                "bytes": fl.get("bytes"),
            }
            for fl in matched
        ]
        ev["frame_numbers"] = frames
        ev["flow_ids"] = [fl.get("flow_id") for fl in matched if fl.get("flow_id")]
        _set(f, "evidence", ev)
        _set(f, "evidence_quality", _evidence_quality(ev))


def attach_arp_evidence(findings, arp_observations, max_frames: int = 50) -> None:
    """Link ARP findings to the ARP frames that produced them.

    ARP traffic carries no TCP/UDP port, so it never enters the flow layer.
    The plugin findings describe the offending MAC in prose; match it against
    ``arp_observations`` (which now carry ``frame_number``) and attach frames.
    """
    import re

    if not arp_observations:
        return
    mac_re = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.I)

    for f in findings or []:
        category = str(_get(f, "category") or "").upper()
        if not category.startswith("ARP_"):
            continue
        ev = _get(f, "evidence") or {}
        if not isinstance(ev, dict):
            ev = {}
        if ev.get("frame_numbers"):
            continue

        mac = str(_get(f, "mac") or "").lower()
        if not mac:
            match = mac_re.search(str(_get(f, "description") or ""))
            mac = match.group(1).lower() if match else ""
        ip = str(_get(f, "ip") or "")

        frames = []
        for obs in arp_observations:
            obs_mac = str(obs.get("src_mac") or "").lower()
            obs_dst = str(obs.get("dst_mac") or "").lower()
            obs_ip = str(obs.get("src_ip") or "")
            if mac and mac not in (obs_mac, obs_dst):
                continue
            if not mac and ip and ip != obs_ip:
                continue
            fn = obs.get("frame_number")
            if fn is not None and fn not in frames:
                frames.append(fn)
            if len(frames) >= max_frames:
                break

        if frames:
            ev.setdefault("frame_numbers", [])
            ev["frame_numbers"] = frames
            ev.setdefault("flows", [])
            ev.setdefault("protocol_fields", [])
            ev.setdefault("feature_values", {})
            _set(f, "evidence", ev)
            _set(f, "evidence_quality", _evidence_quality(ev))


CONDITION_LABELS = {
    "external_destination": "目的地址为外部地址",
    "unknown_port": "服务端口非常用端口",
    "ot_source": "源资产属于现场控制或监控层",
    "long_duration": "观察持续时间较长",
    "strong_periodicity": "连接间隔高度规律",
    "low_drift": "周期漂移很小",
    "many_events": "观察到的连接事件数量充足",
    "many_samples": "样本数量充足",
    "low_dispersion": "间隔波动很小",
    "many_ports": "涉及多个目标端口",
    "few_packets_per_port": "每个端口仅有少量报文",
    "high_syn_ratio": "以 SYN 探测为主",
    "low_handshake_rate": "握手完成比例很低",
}

FEATURE_LABELS = {
    "median_iat_s": ("中位间隔", "秒"),
    "rvc": ("间隔波动（RVC）", ""),
    "autocorr_peak": ("自相关峰值", ""),
    "drift": ("周期漂移", ""),
    "samples": ("样本数", ""),
    "coverage_s": ("观察时长", "秒"),
    "distinct_ports": ("目标端口数", ""),
    "packets_per_port": ("每端口报文数", ""),
    "syn_only_ratio": ("SYN-only 比例", ""),
    "established_ratio": ("握手完成比例", ""),
}


def _evidence_blocks(f, evidence: dict, detection: dict) -> list:
    """Typed evidence blocks: what was observed / what was computed / what it
    means / what it cannot prove. The UI renders these in that order."""
    blocks = []
    flows = evidence.get("flows") or []
    frames = evidence.get("frame_numbers") or []

    observed = []
    for fl in flows[:5]:
        observed.append(
            f"{fl.get('src_ip')}:{fl.get('src_port')} → "
            f"{fl.get('dst_ip')}:{fl.get('dst_port')} "
            f"({fl.get('transport') or '?'}, {fl.get('tcp_state') or '未知状态'})"
        )
    if frames:
        observed.append(f"关联原始帧 {len(frames)} 个")
    if not observed:
        nodes = [str(n) for n in (_get(f, "affected_nodes") or []) if n]
        if nodes:
            observed.append("关联资产：" + "、".join(nodes[:6]))
    if observed:
        blocks.append({"type": "OBSERVED", "title": "观察到的通信", "items": observed})

    stats = []
    for key, value in (evidence.get("feature_values") or {}).items():
        if key not in FEATURE_LABELS or value in (None, ""):
            continue
        label, unit = FEATURE_LABELS[key]
        stats.append(f"{label}：{value}{(' ' + unit) if unit else ''}")
    if stats:
        blocks.append({"type": "STATISTICAL", "title": "统计特征", "items": stats})

    context = []
    category = str(_get(f, "category") or "").upper()
    for cond in (detection.get("matched_conditions") or []):
        cond_s = str(cond)
        # Never leak the raw category code into user-facing evidence.
        if cond_s.upper() == category:
            continue
        context.append(CONDITION_LABELS.get(cond_s, cond_s))
    if context:
        blocks.append({"type": "CONTEXT", "title": "为什么判定为风险", "items": context})

    limits = [str(x) for x in (detection.get("limitations") or []) if x]
    if limits:
        blocks.append({"type": "LIMITATION", "title": "这条证据不能证明什么", "items": limits})
    return blocks


def finalize_findings(
    findings,
    window_start: str = "",
    window_end: str = "",
    visibility: str = VIS_COMPLETE,
    capture_ref: dict | None = None,
) -> list:
    """Fill every P0 field that the rule did not set. Idempotent.

    ``findings`` may be ``RiskFinding`` objects (engine time) or dicts
    (serialized reports / plugin findings). Returns the same list.
    """
    window = {"start": window_start or "", "end": window_end or ""}

    for seq, f in enumerate(findings or [], start=1):
        category = str(_get(f, "category", "") or "")
        status = _get(f, "observation_status") or ""

        if not _get(f, "finding_id"):
            _set(f, "finding_id", new_finding_id(category, seq))
        if not _get(f, "rule_id"):
            _set(f, "rule_id", category or "UNKNOWN")
        if not _get(f, "rule_version"):
            _set(f, "rule_version", RULE_VERSION)

        if not status:
            status = _default_status(category)
            _set(f, "observation_status", status)

        if not _get(f, "confidence"):
            _set(f, "confidence", DEFAULT_CONFIDENCE.get(status, 0.5))

        if not _get(f, "time_window"):
            _set(f, "time_window", dict(window))

        vis = _get(f, "capture_visibility") or VIS_UNKNOWN
        if vis == VIS_UNKNOWN and visibility != VIS_UNKNOWN:
            vis = visibility
            _set(f, "capture_visibility", vis)

        evidence = _get(f, "evidence") or {}
        if not isinstance(evidence, dict) or not evidence:
            evidence = empty_evidence(vis)
            _set(f, "evidence", evidence)
        else:
            evidence.setdefault("frame_numbers", [])
            evidence.setdefault("flows", [])
            evidence.setdefault("protocol_fields", [])
            evidence.setdefault("feature_values", {})
            evidence.setdefault("capture_visibility", vis)
            _set(f, "evidence", evidence)

        if not _get(f, "evidence_quality"):
            _set(f, "evidence_quality", _evidence_quality(evidence))

        detection = _get(f, "detection") or {}
        if not isinstance(detection, dict) or not detection:
            detection = empty_detection()
            detection["matched_conditions"] = [category] if category else []
            detection["limitations"] = [DEFAULT_LIMITATIONS.get(status, "")]
            _set(f, "detection", detection)
        else:
            detection.setdefault("method", "rule")
            detection.setdefault("matched_conditions", [])
            detection.setdefault("limitations", [])
            _set(f, "detection", detection)

        # ── evidence contract v2 (additive) ─────────────────────────────
        links = evidence.get("links")
        if not isinstance(links, dict):
            links = {}
        links.setdefault(
            "flow_ids",
            [x for x in (evidence.get("flow_ids") or []) if x],
        )
        links.setdefault("frame_numbers", list(evidence.get("frame_numbers") or [])[:50])
        evidence["links"] = links
        if capture_ref:
            evidence["capture_ref"] = dict(capture_ref)
        if not evidence.get("blocks"):
            evidence["blocks"] = _evidence_blocks(f, evidence, detection)
        _set(f, "evidence", evidence)

    return findings
