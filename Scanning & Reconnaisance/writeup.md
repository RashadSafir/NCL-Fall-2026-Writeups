## Recon: Cyber Command (Easy)
Challenge: Enumerate the services on the server named `target` and answer the questions.

Artifact(s): live `target` host

- full TCP scan with version detection and default scripts, surfaces everything needed in one shot:
    - `nmap -sV -sC -p- target`

Open ports (services):
- 22/tcp ssh (OpenSSH)
- 23/tcp telnet
- 25/tcp smtp (Postfix)
- 80/tcp http (Caddy)

Notes:
- the cleartext/insecure shell service is the telnet one (as opposed to SSH on 22)
- SMTP leaks a mail host in its `Service Info` line
- the HTTP server injects a custom `X-Flag` header into every response, so the flag drops straight out of the banner:
    - `curl -sI http://target/ | grep -i x-flag`

Q1: What insecure shell service is exposed on target?
- the plaintext shell service from the port list (not SSH)

Q2: Full version string of the service on the lowest TCP port?
- read the `-sV` banner for port 22

Q3: One service reveals a hostname (FQDN), what is it?
- pull it from the SMTP `Service Info` line

Q4: One service responds with a flag, what is it?
- comes straight out of the `X-Flag` response header (curl above)
