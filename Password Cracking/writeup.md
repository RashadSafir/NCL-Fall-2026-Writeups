# Password Cracking

## Not RockYou
Challenge: We found some password hashes on a Liber8tion server that can't seem to be cracked with RockYou. We think they could be cracked with the fasttrack, sqlmap and john lists available on a Kali VM.

Q1:
- ID each hash by length/format first (SHA1 = 40 hex, SHA256 = 64 hex, SHA512 = 128 hex)
- for the ones that live in lookup DBs, a precomputed lookup is fastest: https://crackstation.net/
- for the ones RockYou won't crack, run them against the lists the prompt calls out (fasttrack, sqlmap, the john lists on Kali) with john or hashcat

| User | Hash | Type |
|---|---|---|
| Laura | `ada1ca154329f5472b8a92720618085b93bae856` | SHA1 |
| Jenny | `3335135fc221118fdf7bf24a811be835a59b6fecdf671e22dcbfe4d30ae613ff` | SHA256 |
| Elyse | `dd9b34eacb7e66ecaee6888c7b358d3dc37a6d23f7e2257536e603347d1e329cd0b95ab19b0b6735d5d0ed1b9cee95c4a44dc10fd03b6f5c2687a650938730f1` | SHA512 |

## Rock Your Formats
Artifact(s): file3, file2.ppk, file1.yaml
Challenge: We've got a couple of encrypted files here. Can you figure out what formats they are and crack the passwords using a popular wordlist?

Notes:
- ID each file's format first, don't trust the extension: run `file` on each and check the headers/contents
- once you know the format, use the matching *2john extractor to get a crackable hash, then run it against RockYou
- file1.yaml -> figure out what the YAML actually wraps, extract, crack
- file2.ppk -> PuTTY key, so putty2john then crack
- file3 -> ID the format with `file` first, then the right *2john

Q1: What is the password for `file1.yaml`?
Q2: What is the password for `file2.ppk`?
Q3: What is the password for `file3`?
