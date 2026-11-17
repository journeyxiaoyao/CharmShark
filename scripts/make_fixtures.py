"""Generate synthetic PCAP fixtures for the P0 regression set.

Pure standard library (struct) — no scapy/dpkt needed. Each fixture isolates
one behaviour so ``scripts/evaluate.py`` can assert per-rule detection:

  normal_modbus_polling   1s PLC polling with read/write, full TCP handshakes
  normal_dns_sync         60s DNS from an internal client (periodic but benign)
  attack_beacon_stable    5s C2-like beacon to a public IP, full handshakes
  attack_beacon_jitter    same but with +/-12% jitter
  attack_syn_scan         SYN-only sweep across 60 ports (no replies)
  attack_arp_poison       two MACs claiming the gateway IP + gratuitous ARP

Usage:  python scripts/make_fixtures.py [--out DIR]
"""

from __future__ import annotations

import argparse
import os
import random
import struct

BASE_TS = 1_760_000_000.0
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


# ── packet builders ─────────────────────────────────────────────────────────
def _mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def _ip(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _eth(dst_mac: str, src_mac: str, ethertype: int = 0x0800) -> bytes:
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", ethertype)


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    total = 20 + len(payload)
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident & 0xFFFF,
                       0x4000, 64, proto, 0, _ip(src), _ip(dst))
    head = head[:10] + struct.pack("!H", _checksum(head)) + head[12:]
    return head + payload


def _tcp(sport: int, dport: int, seq: int, ack: int, flags: int,
         src: str, dst: str, payload: bytes = b"") -> bytes:
    offset = (5 << 4) | 0
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF,
                      ack & 0xFFFFFFFF, offset, flags, 8192, 0, 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    chk = _checksum(pseudo + hdr + payload)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF,
                      ack & 0xFFFFFFFF, offset, flags, 8192, 0, chk)
    return hdr + payload


def _udp(sport: int, dport: int, payload: bytes, src: str, dst: str) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 17, length)
    chk = _checksum(pseudo + hdr + payload) or 0xFFFF
    hdr = struct.pack("!HHHH", sport, dport, length, chk)
    return hdr + payload


def _arp(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return (struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + _mac(sha)
            + _ip(spa) + _mac(tha) + _ip(tpa))


def _frame(src: str, dst: str, proto: int, l4: bytes, smac: str, dmac: str,
           ident: int) -> bytes:
    return _eth(dmac, smac) + _ipv4(src, dst, proto, l4, ident)


# ── scenario helpers ────────────────────────────────────────────────────────
class Builder:
    def __init__(self):
        self.packets: list[tuple[float, bytes]] = []
        self._ident = 1000
        self._seq = 5000

    def next_ident(self) -> int:
        self._ident = (self._ident + 1) & 0xFFFF
        return self._ident

    def next_seq(self) -> int:
        self._seq += 1000
        return self._seq

    def tcp_connection(self, t0: float, client: dict, server: dict,
                       sport: int, dport: int, payload: bytes = b"",
                       reply: bytes = b"") -> None:
        """Emit a full handshake + optional data + FIN, timestamps a few ms apart."""
        c_seq = self.next_seq()
        s_seq = self.next_seq()
        steps = [
            (0.000, client, server, SYN, c_seq, 0, b""),
            (0.002, server, client, SYN | ACK, s_seq, c_seq + 1, b""),
            (0.004, client, server, ACK, c_seq + 1, s_seq + 1, b""),
        ]
        if payload:
            steps.append((0.006, client, server, PSH | ACK, c_seq + 1, s_seq + 1, payload))
            steps.append((0.008, server, client, ACK, s_seq + 1, c_seq + 1 + len(payload), b""))
        if reply:
            steps.append((0.010, server, client, PSH | ACK, s_seq + 1, c_seq + 1 + len(payload), reply))
            steps.append((0.012, client, server, ACK, c_seq + 1 + len(payload), s_seq + 1 + len(reply), b""))
        steps.append((0.014, client, server, FIN | ACK, c_seq + 1 + len(payload), s_seq + 1 + len(reply), b""))
        steps.append((0.016, server, client, FIN | ACK, s_seq + 1 + len(reply), c_seq + 2 + len(payload), b""))
        for dt, src, dst, flags, seq, ack, data in steps:
            l4 = _tcp(sport if src is client else dport,
                      dport if src is client else sport,
                      seq, ack, flags, src["ip"], dst["ip"], data)
            self.packets.append((t0 + dt, _frame(src["ip"], dst["ip"], 6, l4,
                                                 src["mac"], dst["mac"], self.next_ident())))

    def syn_only(self, t0: float, src: dict, dst: dict, sport: int, dport: int) -> None:
        l4 = _tcp(sport, dport, self.next_seq(), 0, SYN, src["ip"], dst["ip"])
        self.packets.append((t0, _frame(src["ip"], dst["ip"], 6, l4,
                                        src["mac"], dst["mac"], self.next_ident())))

    def udp(self, t0: float, src: dict, dst: dict, sport: int, dport: int, payload: bytes) -> None:
        self.packets.append((t0, _frame(src["ip"], dst["ip"], 17,
                                        _udp(sport, dport, payload, src["ip"], dst["ip"]),
                                        src["mac"], dst["mac"], self.next_ident())))

    def arp(self, t0: float, op: int, sha: str, spa: str, tha: str, tpa: str) -> None:
        self.packets.append((t0, _eth("ff:ff:ff:ff:ff:ff", sha, 0x0806)
                             + _arp(op, sha, spa, tha, tpa)))


def _modbus_read(tid: int) -> tuple[bytes, bytes]:
    pdu = struct.pack("!BHH", 3, 0, 10)
    req = struct.pack("!HHHB", tid, 0, len(pdu) + 1, 1) + pdu
    data = bytes(range(20))
    pdu_r = struct.pack("!BB", 3, len(data)) + data
    resp = struct.pack("!HHHB", tid, 0, len(pdu_r) + 1, 1) + pdu_r
    return req, resp


def _modbus_write(tid: int) -> tuple[bytes, bytes]:
    pdu = struct.pack("!BHHH", 6, 0, 1, 1)
    req = struct.pack("!HHHB", tid, 0, len(pdu) + 1, 1) + pdu
    return req, req


HMI = {"ip": "10.0.0.10", "mac": "00:1b:1b:00:00:10"}
PLC = {"ip": "10.0.0.20", "mac": "00:1b:1b:00:00:20"}
DNS = {"ip": "10.0.0.53", "mac": "00:1b:1b:00:00:53"}
HOST = {"ip": "10.0.0.50", "mac": "00:1b:1b:00:00:50"}
EXT = {"ip": "93.184.216.34", "mac": "00:00:5e:00:53:50"}
GW = {"ip": "10.0.0.1", "mac": "00:1b:1b:00:00:01"}
ROGUE_A = "00:1b:1b:00:00:66"
ROGUE_B = "00:1b:1b:00:00:77"


# ── scenarios ───────────────────────────────────────────────────────────────
def normal_modbus_polling() -> Builder:
    b = Builder()
    t = BASE_TS
    for i in range(60):
        tid = i + 1
        req, resp = _modbus_write(tid) if i % 15 == 0 else _modbus_read(tid)
        b.tcp_connection(t, HMI, PLC, 50200, 502, req, resp)
        t += 1.0
    return b


def normal_dns_sync() -> Builder:
    b = Builder()
    t = BASE_TS
    for i in range(20):
        name = f"plc{i:02d}.plant.local"
        q = (struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
             + b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
             + b"\x00" + struct.pack("!HH", 1, 1))
        b.udp(t, HOST, DNS, 33000 + i, 53, q)
        t += 60.0
    return b


def _beacon(jitter: float) -> Builder:
    b = Builder()
    rng = random.Random(7)
    t = BASE_TS
    for i in range(120):
        payload = b"\x00" * 16
        b.tcp_connection(t, HOST, EXT, 50000 + i, 4444, payload, b"\x01" * 8)
        step = 5.0
        if jitter:
            step = 5.0 * (1.0 + rng.uniform(-jitter, jitter))
        t += step
    return b


def attack_beacon_stable() -> Builder:
    return _beacon(0.0)


def attack_beacon_jitter() -> Builder:
    return _beacon(0.12)


def attack_syn_scan() -> Builder:
    b = Builder()
    t = BASE_TS
    for port in range(1, 61):
        b.syn_only(t, HOST, {"ip": "10.0.0.100", "mac": "00:1b:1b:00:00:64"},
                   41000 + port, port)
        t += 0.001
    return b


def attack_arp_poison() -> Builder:
    b = Builder()
    t = BASE_TS
    for i in range(10):
        b.arp(t, 2, ROGUE_A, GW["ip"], GW["mac"], GW["ip"])          # claim gateway IP
        b.arp(t + 0.5, 2, ROGUE_B, GW["ip"], GW["mac"], GW["ip"])     # second claimant
        b.arp(t + 1.0, 1, HOST["mac"], HOST["ip"], "00:00:00:00:00:00", GW["ip"])
        t += 2.0
    return b



def normal_ssdp() -> Builder:
    b = Builder()
    t = BASE_TS
    payload = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               b"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
    for i in range(60):
        b.udp(t, HOST, {"ip": "239.255.255.250", "mac": "01:00:5e:7f:ff:fa"}, 49152, 1900, payload)
        t += 1.0
    return b


def normal_mdns() -> Builder:
    b = Builder()
    t = BASE_TS
    q = (struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
         + b"\x0c_services\x07_dns-sd\x04_udp\x05local\x00"
         + struct.pack("!HH", 12, 1))
    for i in range(60):
        b.udp(t, HOST, {"ip": "224.0.0.251", "mac": "01:00:5e:00:00:fb"}, 5353, 5353, q)
        t += 1.0
    return b


def normal_ftp_session() -> Builder:
    b = Builder()
    t = BASE_TS
    srv = {"ip": "10.0.0.60", "mac": "00:1b:1b:00:00:60"}
    steps = [
        (b"220 FTP server ready\r\n", True),
        (b"USER admin\r\n", False),
        (b"331 Password required\r\n", True),
        (b"PASS admin\r\n", False),
        (b"230 Logged in\r\n", True),
        (b"QUIT\r\n", False),
        (b"221 Bye\r\n", True),
    ]
    # one connection, alternating payloads
    c_seq, s_seq = 5000, 9000
    for i, (payload, from_server) in enumerate(steps):
        dt = i * 0.05
        if from_server:
            l4 = _tcp(21, 50200, s_seq, c_seq, PSH | ACK, srv["ip"], HOST["ip"], payload)
            b.packets.append((t + dt, _frame(srv["ip"], HOST["ip"], 6, l4, srv["mac"], HOST["mac"], b.next_ident())))
            s_seq += len(payload)
        else:
            l4 = _tcp(50200, 21, c_seq, s_seq, PSH | ACK, HOST["ip"], srv["ip"], payload)
            b.packets.append((t + dt, _frame(HOST["ip"], srv["ip"], 6, l4, HOST["mac"], srv["mac"], b.next_ident())))
            c_seq += len(payload)
    return b


def probe_ftp_syn_only() -> Builder:
    b = Builder()
    t = BASE_TS
    srv = {"ip": "10.0.0.60", "mac": "00:1b:1b:00:00:60"}
    for i in range(10):
        b.syn_only(t, HOST, srv, 41000 + i, 21)
        t += 0.5
    return b


SCENARIOS = {
    "normal_modbus_polling": normal_modbus_polling,
    "normal_dns_sync": normal_dns_sync,
    "attack_beacon_stable": attack_beacon_stable,
    "attack_beacon_jitter": attack_beacon_jitter,
    "attack_syn_scan": attack_syn_scan,
    "attack_arp_poison": attack_arp_poison,
    "normal_ssdp": normal_ssdp,
    "normal_mdns": normal_mdns,
    "normal_ftp_session": normal_ftp_session,
    "probe_ftp_syn_only": probe_ftp_syn_only,
}


def write_pcap(path: str, packets: list[tuple[float, bytes]]) -> None:
    packets = sorted(packets, key=lambda p: p[0])
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec += 1
                usec -= 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join("tests", "fixtures", "pcap"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    for name, fn in SCENARIOS.items():
        builder = fn()
        path = os.path.join(args.out, name + ".pcap")
        write_pcap(path, builder.packets)
        print(f"{name:26s} {len(builder.packets):5d} packets  -> {path}")


if __name__ == "__main__":
    main()
