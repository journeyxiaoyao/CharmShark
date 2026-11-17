"""v3.7 P0 gate tests: TCP state / visibility / ConnectionEvent lifecycle.

Covers the TCP-01 .. TCP-05 matrix from the design document plus the
"two connections within one second must stay separate" rule (BEACON-04).
"""

from marlinspike.connection import (
    CONNECTION_REFUSED,
    ESTABLISHED,
    FULL_VISIBILITY,
    PARTIAL_VISIBILITY,
    RESET,
    SYN_ACK_SEEN,
    SYN_ONLY,
    classify_event,
)
from marlinspike.engine import OTProtocolDissector


def _flags(syn=False, ack=False, rst=False, fin=False, psh=False):
    return {"syn": syn, "ack": ack, "rst": rst, "fin": fin, "psh": psh, "urg": False}


def _dissector():
    return OTProtocolDissector("dummy.pcap")


def _run(d, packets, return_path=True):
    for ts, src, sport, dst, dport, fl, frame in packets:
        d._track_connection(src, sport, dst, dport, "tcp", ts, fl, frame, 60)
    if return_path:
        d._seen_directions.add((packets[0][3], packets[0][1]))
    d._finalize_connection_events()


# ── TCP-01: canonical direction opposite to the SYN direction ──────────────
def test_tcp01_handshake_detected_when_syn_comes_from_higher_ip():
    d = _dissector()
    # 10.0.0.99 > 10.0.0.10 lexicographically, so the initiator is the "rev" side.
    _run(d, [
        (1000.00, "10.0.0.99", 50000, "10.0.0.10", 4444, _flags(syn=True), 1),
        (1000.02, "10.0.0.10", 4444, "10.0.0.99", 50000, _flags(syn=True, ack=True), 2),
        (1000.04, "10.0.0.99", 50000, "10.0.0.10", 4444, _flags(ack=True), 3),
    ])
    assert len(d.conn_events) == 1
    ev = d.conn_events[0]
    assert ev.initiator == "10.0.0.99"
    assert ev.responder == "10.0.0.10"
    assert ev.tcp_state == ESTABLISHED
    assert ev.visibility_state == FULL_VISIBILITY


# ── TCP-02: only SYN, return path invisible ────────────────────────────────
def test_tcp02_syn_only_partial_visibility():
    d = _dissector()
    _run(d, [(1000.00, "10.0.0.50", 50000, "10.0.0.60", 21, _flags(syn=True), 1)],
         return_path=False)
    ev = d.conn_events[0]
    assert ev.tcp_state == SYN_ONLY
    assert ev.visibility_state == PARTIAL_VISIBILITY


# ── TCP-03: handshake without data / no response afterwards ────────────────
def test_tcp03_syn_ack_seen_is_not_established():
    d = _dissector()
    _run(d, [
        (1000.00, "10.0.0.50", 50000, "10.0.0.60", 4444, _flags(syn=True), 1),
        (1000.02, "10.0.0.60", 4444, "10.0.0.50", 50000, _flags(syn=True, ack=True), 2),
    ])
    ev = d.conn_events[0]
    assert ev.tcp_state == SYN_ACK_SEEN
    assert ev.visibility_state == FULL_VISIBILITY


# ── TCP-04: complete three-way handshake ───────────────────────────────────
def test_tcp04_established():
    d = _dissector()
    _run(d, [
        (1000.00, "10.0.0.50", 50000, "10.0.0.60", 4444, _flags(syn=True), 1),
        (1000.02, "10.0.0.60", 4444, "10.0.0.50", 50000, _flags(syn=True, ack=True), 2),
        (1000.04, "10.0.0.50", 50000, "10.0.0.60", 4444, _flags(ack=True), 3),
        (1000.06, "10.0.0.50", 50000, "10.0.0.60", 4444, _flags(ack=True, psh=True), 4),
    ])
    assert d.conn_events[0].tcp_state == ESTABLISHED


# ── TCP-05: explicit refusal ───────────────────────────────────────────────
def test_tcp05_connection_refused():
    d = _dissector()
    _run(d, [
        (1000.00, "10.0.0.50", 50000, "10.0.0.60", 4444, _flags(syn=True), 1),
        (1000.02, "10.0.0.60", 4444, "10.0.0.50", 50000, _flags(rst=True, ack=True), 2),
    ])
    ev = d.conn_events[0]
    assert ev.tcp_state == CONNECTION_REFUSED
    assert ev.visibility_state == FULL_VISIBILITY


def test_reset_after_established_is_reset():
    state, _ = classify_event(
        {"syn": 1, "synack": 1, "ack": 3, "rst": 1, "fin": 0, "packets": 6},
        "tcp", True,
    )
    assert state == RESET


# ── BEACON-04: two connections inside one second stay separate ─────────────
def test_two_connections_within_one_second_are_separate_events():
    d = _dissector()
    d._track_connection("10.0.0.50", 50000, "10.0.0.60", 4444, "tcp", 1000.00, _flags(syn=True), 1, 60)
    d._track_connection("10.0.0.60", 4444, "10.0.0.50", 50000, "tcp", 1000.02, _flags(syn=True, ack=True), 2, 60)
    d._track_connection("10.0.0.50", 50000, "10.0.0.60", 4444, "tcp", 1000.04, _flags(ack=True), 3, 60)
    d._track_connection("10.0.0.50", 50000, "10.0.0.60", 4444, "tcp", 1000.50, _flags(syn=True), 4, 60)
    d._finalize_connection_events()
    assert len(d.conn_events) == 2
    assert abs(d.conn_events[1].representative_timestamp - d.conn_events[0].representative_timestamp) == 0.5


def test_retransmitted_syn_stays_one_event():
    d = _dissector()
    d._track_connection("10.0.0.50", 50000, "10.0.0.60", 4444, "tcp", 1000.00, _flags(syn=True), 1, 60)
    d._track_connection("10.0.0.50", 50000, "10.0.0.60", 4444, "tcp", 1000.80, _flags(syn=True), 2, 60)
    d._finalize_connection_events()
    assert len(d.conn_events) == 1
    assert d.conn_events[0].tcp_state == SYN_ONLY


def test_dedup_reply_direction_shares_group():
    """DEDUP-02: A -> B beacon plus B -> A replies is one behaviour."""
    from marlinspike.connection import ConnectionEvent, group_events

    a = ConnectionEvent(initiator="10.0.0.1", responder="10.0.0.2", protocol="tcp",
                        responder_port=4444, endpoint_pair=["10.0.0.1", "10.0.0.2"],
                        representative_timestamp=1.0)
    b = ConnectionEvent(initiator="10.0.0.1", responder="10.0.0.2", protocol="tcp",
                        responder_port=4444, endpoint_pair=["10.0.0.1", "10.0.0.2"],
                        representative_timestamp=6.0)
    assert len(group_events([a, b])) == 1


def test_dedup_independent_reverse_behaviours_stay_separate():
    """DEDUP-03: two independent periodic behaviours keep their own groups."""
    from marlinspike.connection import ConnectionEvent, group_events

    a = ConnectionEvent(initiator="10.0.0.1", responder="10.0.0.2", protocol="tcp",
                        responder_port=4444, endpoint_pair=["10.0.0.1", "10.0.0.2"],
                        representative_timestamp=1.0)
    b = ConnectionEvent(initiator="10.0.0.2", responder="10.0.0.1", protocol="tcp",
                        responder_port=5555, endpoint_pair=["10.0.0.1", "10.0.0.2"],
                        representative_timestamp=2.0)
    assert len(group_events([a, b])) == 2


if __name__ == "__main__":
    # pytest is optional in this environment; run the matrix directly.
    import sys
    import traceback

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:  # noqa: BLE001
                failures += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print(f"\n{'(all passed)' if not failures else f'{failures} failed'}")
    sys.exit(1 if failures else 0)
