import hashlib
import hmac

# Inputs

p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)

PKE   = bytes.fromhex("224854c2a0615b0ec6a5313e13a237b94bdda79857e035ed369e353bdec085c7"
                      "0042555cf75266e95e5bb22394471189a464fe5aa2e10ca42b647415023514024d"
                      "11adb22e4ee00f08b446de7af030ea59abbad95f510a83d0ef9aa58121e72d457c"
                      "d6096371b451f7eee4c368c5d3c6e2352b9680b4801ec8c1b2681f8d9df12ad631"
                      "1e200d23db49bcb8c17a3a83986a8e09225877120de2f8d1271810b447e5583836"
                      "031450325907e73d9bbfdd00d05872b2be6ad0a0d047bbc28c0e33d5")

privR = int("f14310ea480d86979562093f7a32324c5aa1fe4b333ec1ad6c3126c7275fde25"
            "f0b1628bb2521b4bd8fd6837df29577c527514e0eac2c85ec6953a60f85fc491"
            "6cbfcdac57fb6cc9061a9f4ac9de0718b4ec6b0cb065b4458d0e45852957d48f"
            "596269ea61dd20e61c14a1dd82e3446397a2af7711502ebee5d04587b186ce51"
            "a960451d5ac5aaa4bb42bce1dac9a43d3737858e2cb4cb6b50ade2fb34f71081"
            "5fb91fbb091739f6181b7c53d737c4ac27ca0b98e4f22c2f88ef9f9421aa88db", 16)

N1 = bytes.fromhex("13c6fa78d61c5f8fb08bbe82de2ec5e1") #Enrollee Nonce

N2 = bytes.fromhex("4a7ad98d501ac2f14e8b1503ee7765f9") #Registrar Nonce

MAC = bytes.fromhex("50c7bf3e91a4") # Enrollee Mac

# Computes PKE ^ privR mod p
shared = pow(int.from_bytes(PKE, "big"), privR, p).to_bytes(192, "big")

# Compute hashed key
DHKey = hashlib.sha256(shared).digest()

# Compute Key Derivation Key
KDK = hmac.new(DHKey, N1 + MAC + N2, hashlib.sha256).digest()

# Compute the Key Derivation Function

def kdf(key, total_bits):
    personal = b"Wi-Fi Easy and Secure Key Derivation"
    out = b""
    i = 1
    while len(out) * 8 < total_bits:
        out += hmac.new(key, i.to_bytes(4,"big") + personal + total_bits.to_bytes(4,"big"),
                        hashlib.sha256).digest()
        i += 1
    return out[:total_bits // 8]


# Take the 3 keys and pack together to get AuthKey + KeyWrapKey + EMSK
keys = kdf(KDK, 640)
AuthKey = keys[:32]

# AuthKey (first 32 bytes of the KDF output) is now in `AuthKey`.
# Feed it into the PIN brute-force (see pin_bruteforce.py) rather than
# printing the value here.
