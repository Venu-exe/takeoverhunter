"""Pure-Python DNS resolver (CNAME + A/AAAA). Zero external dependencies."""
import socket
import struct

DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]


def _dns_query(name, qtype, timeout=4, servers=None):
    servers = servers or DNS_SERVERS
    for server in servers:
        try:
            tid = 0x1234
            flags = 0x0100
            header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
            qname = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\x00"
            question = qname + struct.pack("!HH", qtype, 1)
            packet = header + question
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(512)
            sock.close()
        except Exception:
            continue
        if len(data) < 12:
            continue
        _tid, _flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        off = 12
        for _ in range(qd):
            off = _skip_name(data, off)
            off += 4
        results = []
        for _ in range(an):
            off = _skip_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            if rtype == 5:
                results.append((5, _decode_name(data, off)))
            elif rtype == 1 and rdlen == 4:
                results.append((1, socket.inet_ntoa(data[off:off + 4])))
            elif rtype == 28 and rdlen == 16:
                results.append((28, socket.inet_ntop(socket.AF_INET6, data[off:off + 16])))
            off += rdlen
        if results:
            return results
    return []


def _skip_name(data, off):
    while True:
        if off >= len(data):
            return off
        length = data[off]
        if length == 0:
            return off + 1
        if (length & 0xC0) == 0xC0:
            return off + 2
        off += length + 1


def _decode_name(data, off):
    labels = []
    jumped = False
    original_off = off
    safety = 0
    while safety < 64:
        safety += 1
        if off >= len(data):
            break
        length = data[off]
        if length == 0:
            off += 1
            break
        if (length & 0xC0) == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                original_off = off + 2
            off = ptr
            jumped = True
            continue
        off += 1
        labels.append(data[off:off + length].decode("ascii", "replace"))
        off += length
    if jumped:
        off = original_off
    return ".".join(labels).rstrip(".") + "."


def resolve_cname(host, timeout=4, servers=None):
    """Resolve CNAME chain. Returns (immediate_cname, chain_list, ip_list)."""
    chain = []
    current = host.rstrip(".")
    seen = set()
    ip_list = []
    for _ in range(10):
        if current in seen:
            break
        seen.add(current)
        answers = _dns_query(current, 5, timeout, servers)
        cname_found = None
        for typ, val in answers:
            if typ == 5:
                cname_found = val.rstrip(".")
                break
        if cname_found and cname_found.lower() != current.lower():
            chain.append(cname_found)
            current = cname_found
            continue
        a_answers = _dns_query(current, 1, timeout, servers)
        for typ, val in a_answers:
            if typ == 1:
                ip_list.append(val)
        break
    immediate = chain[0] if chain else None
    return immediate, chain, ip_list
