"""ConnectionEvent layer (v3.7).

Packet → Flow → ConnectionEvent → RiskFinding.

A ``Flow`` is a bidirectional 5-tuple aggregate. A ``ConnectionEvent`` is one
*connection attempt* inside that flow: several SYN/data/FIN packets that belong
to the same connection collapse into one event with a single representative
timestamp. Beacon cadence is measured between events, never between packets —
and never by merging events that merely happen to be close in time.

TCP state and capture visibility are separate axes:

    tcp_state         SYN_SENT / SYN_ACK_SEEN / ESTABLISHED / SYN_ONLY /
                      CONNECTION_REFUSED / RESET / UNKNOWN
    visibility_state  FULL_VISIBILITY / PARTIAL_VISIBILITY / UNKNOWN

A lone SYN with no observed return path is ``SYN_ONLY + PARTIAL_VISIBILITY``:
it does not prove the target refused the connection.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── TCP states ─────────────────────────────────────────────────────────────
SYN_SENT = "SYN_SENT"
SYN_ACK_SEEN = "SYN_ACK_SEEN"
ESTABLISHED = "ESTABLISHED"
SYN_ONLY = "SYN_ONLY"
CONNECTION_REFUSED = "CONNECTION_REFUSED"
RESET = "RESET"
UNKNOWN_STATE = "UNKNOWN"

# ── visibility ─────────────────────────────────────────────────────────────
FULL_VISIBILITY = "FULL_VISIBILITY"
PARTIAL_VISIBILITY = "PARTIAL_VISIBILITY"
UNKNOWN_VISIBILITY = "UNKNOWN"

#: gap after which a new packet on the same 5-tuple starts a new event
NEW_CONNECTION_GAP_S = 300.0
#: a retransmitted SYN is recognised by this window (seconds)
SYN_RETRANSMIT_WINDOW_S = 3.0


@dataclass
class ConnectionEvent:
    event_id: str = ""
    #: unordered endpoint pair, e.g. ["10.0.0.5", "10.0.0.6"]
    endpoint_pair: list = field(default_factory=list)
    initiator: str = ""
    responder: str = ""
    initiator_port: int = 0
    responder_port: int = 0
    protocol: str = ""              # transport: tcp / udp
    source_port: int = 0            # initiator side
    destination_port: int = 0       # responder side
    start_timestamp: float = 0.0
    end_timestamp: float = 0.0
    representative_timestamp: float = 0.0
    timestamp_source: str = "FIRST_PACKET"   # FIRST_SYN / FIRST_PACKET
    packet_count: int = 0
    byte_count: int = 0
    tcp_state: str = UNKNOWN_STATE
    visibility_state: str = UNKNOWN_VISIBILITY
    packet_references: list = field(default_factory=list)
    # counters used for classification (not part of the public contract)
    counts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "endpoint_pair": list(self.endpoint_pair),
            "initiator": self.initiator,
            "responder": self.responder,
            "initiator_port": self.initiator_port,
            "responder_port": self.responder_port,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "start_timestamp": self.start_timestamp,
            "end_timestamp": self.end_timestamp,
            "representative_timestamp": self.representative_timestamp,
            "timestamp_source": self.timestamp_source,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "tcp_state": self.tcp_state,
            "visibility_state": self.visibility_state,
            "packet_references": list(self.packet_references),
        }


def classify_event(counts: dict, transport: str, return_path_visible: bool):
    """Return ``(tcp_state, visibility_state)`` for one connection event.

    ``counts`` holds syn / synack / ack / rst / fin / packets.
    ``return_path_visible`` is True when at least one packet was observed from
    the responder back to the initiator anywhere in the capture.
    """
    if transport != "tcp":
        return UNKNOWN_STATE, (FULL_VISIBILITY if return_path_visible else PARTIAL_VISIBILITY)

    syn = int(counts.get("syn", 0))
    synack = int(counts.get("synack", 0))
    ack = int(counts.get("ack", 0))
    #: ACKs sent by the *initiator*. A SYN-ACK carries the ACK flag too, so the
    #: aggregate ACK count cannot prove the three-way handshake completed.
    init_ack = int(counts.get("init_ack", 0))
    rst = int(counts.get("rst", 0))
    packets = int(counts.get("packets", 0))

    # Resets take precedence: an aborted connection is RESET even if the
    # handshake had completed earlier.
    if rst and syn and not synack:
        state = CONNECTION_REFUSED
    elif rst:
        state = RESET
    elif syn and synack and init_ack:
        state = ESTABLISHED
    elif syn and synack:
        state = SYN_ACK_SEEN
    elif syn and not synack:
        state = SYN_ONLY
    elif syn:
        state = SYN_SENT
    else:
        state = UNKNOWN_STATE

    if state == ESTABLISHED:
        visibility = FULL_VISIBILITY if return_path_visible else PARTIAL_VISIBILITY
    elif state in (CONNECTION_REFUSED, RESET):
        visibility = FULL_VISIBILITY
    elif state == SYN_ONLY:
        # No SYN-ACK: either filtered or the return path is not visible.
        visibility = FULL_VISIBILITY if return_path_visible else PARTIAL_VISIBILITY
    elif state in (SYN_SENT, SYN_ACK_SEEN):
        visibility = FULL_VISIBILITY if return_path_visible else PARTIAL_VISIBILITY
    else:
        visibility = PARTIAL_VISIBILITY if not return_path_visible else FULL_VISIBILITY

    return state, visibility


def group_key(event: ConnectionEvent) -> tuple:
    """Dedupe / analysis key: unordered pair + real initiator + service port.

    Using the initiator (not the canonical direction) is what makes
    ``A -> B beacon + B -> A replies`` collapse into one group while two
    independent periodic behaviours keep separate groups.
    """
    pair = tuple(sorted(event.endpoint_pair))
    return (pair, event.initiator, event.protocol, event.responder_port)


def group_events(events) -> dict:
    groups: dict = {}
    for ev in events:
        groups.setdefault(group_key(ev), []).append(ev)
    for key in groups:
        groups[key].sort(key=lambda e: e.representative_timestamp)
    return groups
