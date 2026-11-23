import sys

ROUTES = {0: "TRANSPORT_FLOOD", 1: "FLOOD", 2: "DIRECT", 3: "TRANSPORT_DIRECT"}
PAYLOADS = {4: "ADVERT", 5: "GRP_TXT"}


def field(name, data):
    print(f"  {name:<12} {data.hex().upper()}")


def advert(p):
    field("pubkey", p[0:32])
    field("timestamp", p[32:36])
    field("signature", p[36:100])
    app = p[100:]
    flags = app[0]
    field("flags", app[0:1])
    i = 1
    if flags & 0x10:
        field("lat", app[i:i + 4]); field("lon", app[i + 4:i + 8]); i += 8
    if flags & 0x20:
        field("feat1", app[i:i + 2]); i += 2
    if flags & 0x40:
        field("feat2", app[i:i + 2]); i += 2
    if flags & 0x80:
        field("name", app[i:])


def grp_txt(p):
    field("chan_hash", p[0:1])
    field("mac", p[1:3])
    field("ciphertext", p[3:])


path = sys.argv[1] if len(sys.argv) > 1 else "raw_packets.txt"
out = sys.argv[2] if len(sys.argv) > 2 else "packets_split.txt"
lines = [l.strip() for l in open(path) if l.strip()]
sys.stdout = open(out, "w")

for n, line in enumerate(lines, 1):
    b = bytes.fromhex(line)
    h = b[0]
    route, ptype = h & 3, (h >> 2) & 0xF
    i = 1
    if route in (0, 3):  # transport codes present
        field("transport", b[i:i + 4]); i += 4
    plen = b[i]; i += 1
    print(f"Packet {n}: {ROUTES[route]} / {PAYLOADS.get(ptype, ptype)} / v{(h >> 6) + 1}")
    field("path_len", b[i - 1:i])
    if plen:
        field("path", b[i:i + plen])
    payload = b[i + plen:]
    {4: advert, 5: grp_txt}.get(ptype, lambda p: field("payload", p))(payload)
    print()