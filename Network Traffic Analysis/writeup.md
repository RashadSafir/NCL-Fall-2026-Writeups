# Network Traffic Analysis

## Firehose (Easy)
Artifact(s): conference.pcap
Challenge: Our administrator captured network traffic at a conference. Analyze the traffic that went over that network.

Tools: Wireshark

Q1: What is tdavis-MAC's IPv4 address?
- find the host by name (mDNS/hostname traffic), read its IPv4

Q2: What is its IPv6 IP?
- same host, read its IPv6 (link-local) off its traffic

Q3: Excluding DNS, which TCP destination port does tdavis-MAC try to connect to on the most unique hosts (googlecast)?
- filter to traffic from the host over TCP: `ip.src == <host-ip> && tcp`
- skim the TCP dest ports in play (a couple of candidates)
- filter each candidate: `ip.src == <host-ip> && tcp.dstport == <port>`, compare how many unique hosts each one reaches, the one hitting the most unique dests is it

Q4: It also looks for a Drobo file server via UDP broadcasts. What port?
- start with the broadcasts: `udp && (ip.dst == 255.255.255.255 || eth.dst == ff:ff:ff:ff:ff:ff)`
- group by port: Statistics -> Conversations -> UDP (a couple of ports show up)
- drop the one that's a known service (137 = NetBIOS name service), the other is the Drobo port

Q5: When it syncs time it sends NTP to a single server. What's the server IP?
- filter NTP, read the server IP off the request/response

Q6: Based on the first octet of the NTP server, what company runs it?
- whois the NTP server IP, read the registered org

Q7: Based on the MAC address, what company made the laptop?
- look at the host's MAC (Ethernet frame), resolve the OUI (vendor prefix) to a manufacturer

## Enmeshed
Artifact(s): access.png, raw_packets.txt
Challenge: Your suspects left a phone unlocked and you were able to grab the channel information for their private chat, along with the captured traffic of their discussion. Can you tell what they're planning?

Note: this uses MeshCore, so understand the packet format first. A QR in the artifact points to MeshCore, a simple, secure, off-grid mesh comms system.

Parsing a MeshCore header:
- first byte is a bitfield. e.g. `11` = `00010001` = `00 0100 01`:
    - route type (`01` = ROUTE_TYPE_FLOOD, flood routing)
    - payload type (`0100` = PAYLOAD_TYPE_ADVERT, node advert; `0101` = PAYLOAD_TYPE_GRP_TXT, group text)
    - version (`00` = v1, 1-byte src/dest hashes, 2-byte MAC)

ADVERT packets lay out as:
```
path_len | pubkey (32B) | timestamp (4B) | signature (64B) | flags | lat (4B) | lon (4B) | name
```
- the trailing `name` is ASCII hex, decode it to get the node's display name (that's how you attribute a node to a person)
- lat/lon are little-endian fixed-point: read the 4 bytes LE, for values over 2^31 subtract 2^32 for the signed value, then divide by 1,000,000

GRP_TXT packets lay out as:
```
path_len | chan_hash (1B) | mac (2B) | ciphertext
```
- chan_hash ties the message to a channel, ciphertext is the encrypted body
- to read the messages you need the channel key (Q2), then decrypt each ciphertext

Provided packets (from raw_packets.txt), parse each with the layout above:
- packets 1-2: ADVERT (decode the name, and for located nodes the lat/lon)
- packets 3-8: GRP_TXT on the same channel (chan_hash 6B), decrypt with the channel key

Q1: What is the radio technology used between the two nodes?
- follow the QR in the artifact to ID the mesh platform

Q2: What 128-bit hex key encrypts the messages between them?
- the channel info grabbed off the unlocked phone carries the channel's symmetric key, pull the 128-bit key from the channel config

Q3: Where is Catherine transmitting from? (format: MajorCity, XX)
- find which advert decodes to the name Catherine, decode that packet's lat/lon with the LE fixed-point method above, reverse-geocode to a city/region

Q4: What does Catherine intend to bring back?
- decrypt the group-text packets with the channel key and read the chat

Q5: What specialty shop closest to Catherine's location likely provided the goods?
- using her location (Q3) and what she's bringing back (Q4), find the nearest matching shop on a map

Q6: What agency might derail the weekend plans?
- infer from the chat (a cross-border trip) which agency would be involved

## Wifi PCAP (Hard)
Artifact(s): capture.pcap, registrar_dhpriv.txt
Challenge: We obtained a packet capture of a WPS handshake and the registrar's DH private key from a compromised Liber8tion agent's device. The wireless network uses a weak PRNG seeded with Unix time for WPS nonce generation. Recover info about the network from this capture.

Background, why WPS is attackable here:
- WPS is a legacy standard (2006) for connecting without typing a passphrase
- 8-digit numeric PIN, verified in two halves (first 4 digits, next 3), 8th digit is a checksum of the first 7
- this enables an offline Pixie-Dust-style attack:
    - router answers a WPS start with M1/M2/M3
    - M3 has HMAC commitments to each PIN half (E-Hash1/E-Hash2) that prove knowledge of each half without revealing it, plus nonces (E-S1/E-S2) protecting those hashes
    - the AuthKey that keys those HMACs comes from the DH exchange, which is why the leaked registrar DH private key matters
    - vulnerable chipsets make predictable "random" numbers; here the network uses a weak PRNG seeded with Unix time for the WPS nonces
    - once you recover the predictable nonce, the only unknown left in each hash is the PIN half, so you brute force it

Q1: What is the Access Point's MAC address?
- read the source MAC of M1

Q2: What is the manufacturer of the AP?
- read the EAP / Manufacturer field

Q3: What is the model name of the AP?
- read the EAP / Model Name field

Q4: What is the bit-length of the DH group WPS uses for key exchange? (integer only)
- WPS uses a fixed, standardized Diffie-Hellman MODP group (Group ID 5), look up that group's bit length in the WPS spec / RFC 3526

Q5: What is the AP's PIN?

Provided handshake values (from the capture + leaked file, these are inputs):
```
M1:
  Enrollee Nonce:       13c6fa78d61c5f8fb08bbe82de2ec5e1
  Enrollee Public Key:  224854c2a0615b0ec6a5313e13a237b94bdda79857e035ed369e353bdec085c7
                        0042555cf75266e95e5bb22394471189a464fe5aa2e10ca42b647415023514024d
                        11adb22e4ee00f08b446de7af030ea59abbad95f510a83d0ef9aa58121e72d457c
                        d6096371b451f7eee4c368c5d3c6e2352b9680b4801ec8c1b2681f8d9df12ad631
                        1e200d23db49bcb8c17a3a83986a8e09225877120de2f8d1271810b447e5583836
                        031450325907e73d9bbfdd00d05872b2be6ad0a0d047bbc28c0e33d5

M2:
  Registrar Public Key: f63d33037ceeec960f31a949a1180e034668d38bb93ee13f91d7032690ae6b62
                        e477fd13c0d448cbe3bba2cc64b843ef67034773e812fac8955c6b0196cbadbdde
                        36a2e45e97a7b2f21c1a76a939d91be0da59e9ab3bce50064d14dddc8b22bd90b2
                        48439ddd905aed7afe530237d89faf94ef3ec885c5fee228e11b860bda735bd604
                        2ecb10ee80e31aa2e3bb0f4c8df26de0fe1a88dfa86be6fa9af517615416585688
                        733e947b07c181acc02adc3fb409e50ec7c6b11f0bc2b6f59eadf60c
  Registrar Nonce:      4a7ad98d501ac2f14e8b1503ee7765f9

M3:
  E-Hash1: 9ec639fd84ec2c9859abdb630ea6444cf32dc6c598ae0916c9fe8e857348e808
  E-Hash2: a741a38d8f7540822bed717b0e5921545339cef7efe020bda780043e48fd5c51

Registrar DH private key (leaked file):
  f14310ea480d86979562093f7a32324c5aa1fe4b333ec1ad6c3126c7275fde25...
```

Deriving the AuthKey:

| Value | What it is | Where it's from |
|---|---|---|
| `p` | the prime modulus | WPS standard (RFC 3526) |
| `g` | the generator (2) | WPS standard |
| `PKE` | enrollee's public key (`A = g^a mod p`) | M1 |
| `privR` | registrar's private key | leaked file |

steps:
1. compute the shared secret: `shared = PKE^privR mod p`
2. hash it to remove structure (the raw 192-byte DH output is structured): `DHKey = SHA256(shared)`
3. derive the Key Derivation Key: `KDK = HMAC_SHA256(DHKey, N1 || MAC || N2)`
4. run the WPS KDF to stretch the KDK: WPS needs 640 bits (80 bytes) but HMAC-SHA256 emits 256 bits at a time, so iterate and concatenate. the first 32 bytes of that output are the AuthKey

Recovering the predictable nonces:

the PIN-half hashes are:
```
E-Hash1 = HMAC(AuthKey, E-S1 || PSK1 || PKE || PKR)
E-Hash2 = HMAC(AuthKey, E-S2 || PSK2 || PKE || PKR)
```
E-S1 / E-S2 aren't truly random, they come from a time-seeded generator. to recover them:
- use the Enrollee Nonce N1 (known from M1) as ground truth: the right seed is the one whose PRNG stream reproduces N1
- general loop:
    ```python
    for candidate_seed in [capture_time - window .. capture_time + window]:
        seed the PRNG
        draw bytes the same way the device does
        if first nonce produced == N1:
            found the seed -> keep drawing to get E-S1, E-S2
    ```
- pin down which PRNG the device uses by testing common ones against N1 as ground truth (I tested): glibc `rand()`, MSVC's LCG, ANSI C `rand()`, Park-Miller / minstd LCGs, Python's Mersenne Twister
- brute force across each PRNG and every seed in the time window, generating 16 bytes and comparing to N1. also account for small unknowns: which byte of each `rand()` output to take, endianness, and whether N1 was the 1st/2nd/3rd value drawn
- the first packet's timestamp gives the center of the search window (I used a +/- 1800-second window around the capture time)

example ANSI C `rand()` stream generator used for the search:
```python
def stream(seed, n):          # ANSI C rand(): next 'n' bytes from this seed
    out = []
    for _ in range(n):
        seed = (seed * 1103515245 + 12345) % 2**31
        out.append((seed >> 16) & 0xff)
    return bytes(out)

for seed in range(capture_time - 1800, capture_time + 1800):
    if stream(seed, 16) == N1:
        print("seed:", seed)
        break
```
once the seed is found, draw the first 64 bytes to split out the four 16-byte values (N1, N2, then E-S1 and E-S2):
```python
s = stream(found_seed, 64)
# s[0:16]  = N1
# s[16:32] = N2
# s[32:48] = E-S1
# s[48:64] = E-S2
```

Recovering the PIN:

with the AuthKey and both E-S nonces known, every secret in the hash equations is known except the PIN halves. WPS transmits the PIN split in half, each half turned into a PSK value (an HMAC keyed by the AuthKey, so it's unique to this handshake):
```
E-Hash1 = HMAC(AuthKey, E-S1 || PSK1 || PKE || PKR)
E-Hash2 = HMAC(AuthKey, E-S2 || PSK2 || PKE || PKR)
```
- brute force the first half (first 4 PIN digits) and the second half (next 3 digits, with the 8th as the checksum) independently, computing each candidate's PSK and checking it against E-Hash1 / E-Hash2
- the matching halves reassemble into the AP's PIN

helper scripts in this folder: `auth_key.py`, `seed_finder.py`, `pin_bruteforce.py`, which implement the three stages above (AuthKey derivation, PRNG/seed recovery, PIN brute force)

status: didn't finish this one. the seed I pulled from the time-window PRNG search ended up being wrong, so the E-S1/E-S2 values from it didn't hold and I never got the actual PIN (Q5). leaving the methodology up since the approach is right, the seed recovery is just where it falls apart, and everything after it depends on that
