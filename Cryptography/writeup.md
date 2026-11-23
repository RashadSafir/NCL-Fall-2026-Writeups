# Cryptography

## Cooking With This XOR That
Challenge: We have found four messages from Liber8tion we believe were encoded using a variety of XOR schemes with CyberChef and sent in base64. If they used a key for the encoding, it was the key xor. Decode each message and submit the entire message so we can stop whatever they have planned.

Tools: CyberChef

Notes:
- each message is base64 first, so start with a `From Base64`
- after that it's XOR-encoded, so work through CyberChef's XOR ops to find the scheme per message (plain XOR, repeating-key XOR, etc.)
- the hint "if they used a key, it was the key xor" tells you which XOR variant to lean on

Q1: LAcXWAkbChwGWB8TCxwFFx0WWAYBWD0gMSA+OSQiOiUqMSkwMw==
Q2: LAcXdBsAQxwLB08eBVMDFhwBE08bFwA6J3YYGR4JAR0SBxoZDQY=
Q3: LAcXDHN/ZQEbRXF6NgINWXBpeRkaWVFNDwYBWlFUCBgCSUhJGQ==
Q4: PA1FRgkaBwYcSFAREgAEGB0WREkaU3YSCxwcBQsQFQIDDQsVDlg=
- for Q4: the output differential across the messages gives you the first plaintext byte, and from that you can back out the single-byte XOR key, then decode the rest with it

## Three is a Crowd
Challenge: We've managed to intercept three transmissions from Liber8tion's internal communications. One of them we've already cracked. Can you crack the others?

Artifact:
Three internal memos were archived using the same faulty encryption script. One of them we already recovered from an old backup.

```
Ciphertexts = [
  "bgJ/UsO4oEN5ygvJ8pQ7/y4sLpIDAiU1a0lr2FkYKSaGwD4W4ku3HYg6/hrWWxCJfINzmh/i7fisgoN++7CJ0uNucrq1Bhr/6PWzcB0wWep2O02i1Edrd6P4AuMbfXYB",
  "R1gHRhsuLbzbWCGo0iJ7z/86EEcbKV6zFXNsc9r36v/p4vb8+D1cWFi7eiL8OY7ad6BHoURRXvsLzgLCL3z4Dwh9SD/ZWR4dxqY5t0da/m6kBPimr/gS4l0Ngb2warms",
  "RkkLWwA5cu6AFDngxHtn1bc0AgsZZkG1D3N0NJXNovis4/Pz7D1zWRGMUALxG7/lVuQc9VUFHr9lxEzAKS7BCANrCSeaQBgAxu8+o0dJ6D+kHv+ip/ZAqxpF1b3+Je6i"
];

Known Plaintext = "Reminder: the on-call rotation begins Friday evening and ends Monday morning as usual.";
```

Q1: What is the flag?
- it's a reused-keystream (many-time pad) problem
- stream cipher is C = P XOR K, and decryption is the same op since XOR self-cancels: C XOR K = P
- reusing K across messages is the hole:
    - C1 = P1 XOR K, C2 = P2 XOR K
    - C1 XOR C2 = P1 XOR P2 (the K cancels out)
- we know one plaintext, so recover the keystream: K = C1 XOR P1
- then decrypt the rest: P2 = C2 XOR C1 XOR P1 (two chained XORs plus the known plaintext)

## Collision
Artifact(s): collision.pyc
Challenge: We found a file that doesn't look encrypted, but the code might be scrambled. Can you figure it out?

Q1: Using file, what file type is the .pyc file you downloaded? (Format: file's output varies so the answer checker for this question is quite permissive)
- run `file collision.pyc` and read the type; it tells you the CPython bytecode version you need next

Q2: What is the flag found from reverse engineering the source from collision.pyc?
- decompile the bytecode back to source (match the decompiler to the CPython version from Q1), then read the logic
- status: didn't finish this one, never decompiled it far enough to pull the flag
