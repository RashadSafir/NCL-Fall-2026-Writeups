# NCL Fall 2026: Individual Game Write-ups

My write-ups for the National Cyber League (NCL) Fall 2026 Individual Game. Each one goes through the methodology, tools, and techniques I used to work a challenge.

Per the NCL write-up guidelines, these only go over the approach. No flags, passwords, keys, or other answers are included.

## About NCL

National Cyber League is a cybersecurity competition that's hosted once a semester. The individual game is a timed CTF that goes over multiple categories, and gets scored on accuracy and speed.

The National Cyber League is a performance-based cybersecurity competition. The Individual Game is a timed, hands-on CTF spread across the categories below, scored on accuracy and speed.

## Results

- **Overall rank:** 839 / 5961
- **Percentile:** 86th
- **Score:** 1900
- **Scouting report (Cyber Skyline):** https://cyberskyline.com/report/WAX2WF7L879G

The Certificate of Participation and the full Scouting Report PDF are in [`docs/`](docs/).

## Categories

| Category | Challenges | Write-up |
|---|---|---|
| Cryptography | Cooking With This XOR That (M), Three is a Crowd (M), Collision (M) | [writeup](Cryptography/writeup.md) |
| Exploitation & Enumeration | Cyber Command (E), Vuln Scanner (M) | [writeup](Exploitation%20%26%20Enumeration/writeup.md) |
| Forensics | Fuzzy (H), Browsing (M) | [writeup](Forensics/writeup.md) |
| Log Analysis | Choclympic Peaks (E), Grand Theft Log (M), 24 hours of Le Zook (H) | [writeup](Log%20Analysis/writeup.md) |
| Network Traffic Analysis | Firehose (E), Enmeshed, Wifi PCAP (H) | [writeup](Network%20Traffic%20Analysis/writeup.md) |
| OSINT | Wordsmithing (M), Barcode (M) | [writeup](OSINT/writeup.md) |
| Password Cracking | Not RockYou, Rock Your Formats | [writeup](Password%20Cracking/writeup.md) |
| Scanning & Reconnaisance | Recon: Cyber Command (E) | [writeup](Scanning%20%26%20Reconnaisance/writeup.md) |

(E = Easy, M = Medium, H = Hard)

## Tooling

Tools I used across these challenges:
- Wireshark
- CyberChef
- nmap
- john / hashcat
- CrackStation
- Python

## Helper scripts

The Wifi PCAP (WPS) challenge has supporting Python in [`Network Traffic Analysis/`](Network%20Traffic%20Analysis/):

- `auth_key.py` - derives the WPS AuthKey from the DH exchange
- `seed_finder.py` - recovers the time-seeded PRNG seed and the E-S1/E-S2 nonces
- `pin_bruteforce.py` - brute forces the two PIN halves against E-Hash1/E-Hash2

## Notes

A few of the harder challenges I did not fully solve. Those are marked inline in the relevant write-up so the methodology is still there for reference:

- Cryptography / Collision (Q2)
- Forensics / Fuzzy (Q3)
- Network Traffic Analysis / Wifi PCAP (Q5)

I only did my write-up based on methodology/tools/techniques. No challenge answers were included. 
