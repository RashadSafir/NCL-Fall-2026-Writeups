## Choclympic Peaks (Easy)
Challenge: Choclympic Peaks, a small one-person chocolate shop, is a few days away from announcing a brand new seasonal bar. Before the announcement went out, photos and details of the unreleased treat show up in a chocolate fan forum. The owner pulled their web server's access logs, help them figure out how the leak happened, and exactly what got out.
Artifact(s): choclympic_peaks_log.log

Notes:
- normal customer flow is basically: /index.html -> /products -> /products/<item> -> product-image fetch with `?file=<item>.jpg` -> /cart/add -> /checkout
- anything hitting that `file=` param with something other than a plain `<item>.jpg` stands out
- filter for traversal sequences:
    - `grep '\.\.' choclympic_peaks_log.log`
- only one IP shows up, once per day across three days, always right after midnight

Q1: What IP did the attacker use across all three days?
- day 1: browses normal, then probes a single `../<item>.jpg` (404)
- day 2: walks up with `../../`, `../../../`, URL-encoded `..%2f..%2f...`, lands a staging dir listing (200s)
- day 3: pulls the staged `.json` + `.jpg`
- the one repeat offender in the `..` filter is your answer

Q2: Exact User-Agent string the attacker used?
- everyone else in the log is ancient IE/Opera/Firefox 3.x junk, the attacker is the only modern browser UA
- isolate that odd-one-out UA off the traversal lines

Q3: Which path on the site was vulnerable to directory traversal?
- the product-image endpoint takes a `file=` param and passes it straight to the filesystem with no sanitization
- `../` escapes the image folder, so the request path carrying that `file=` param is the vuln

What got out (context, not graded answers):
- system files via both raw and URL-encoded `..%2f` (so no decode-based filter either)
- a staging directory listing -> the unreleased product's json + photo that ended up on the forum

## Grand Theft Log (Medium)
Challenge: A small nonprofit's website has been running the same WordPress install for years without much attention from an administrator. A security-conscious volunteer noticed the site's own web server log was reachable over HTTP and wants it to be reviewed for anything an attacker might have found first. Can you help?
Artifact(s): grand_theft_log_log.log

Notes:
- log is CEF: `CEF:0|Vendor|Product|Version|StatusCode|Name|Severity|extensions`
- every line is the same vendor/product/version, so the header gives up the server version for free:
    - `cut -d'|' -f2-4 grand_theft_log_log.log | sort | uniq -c`

Q1: What version of the web server generated this log?
- read the Product/Version straight off the CEF header (all lines identical)

Q2: What version of WordPress is running?
- WP tags its core scripts with `?ver=<wp version>` by default
    - `grep -oE 'ver=[0-9][^& ]*' grand_theft_log_log.log | sort | uniq -c | sort -rn`
- most `ver=` values are jQuery or dated asset stamps (20100531 etc.), the real one rides a WP core file (e.g. comment-reply.js)

Q3: Path to the publicly-accessible web-log directory?
- count the top-level directories:
    - `grep -oE 'request=/[^/ ?]*/' grand_theft_log_log.log | sort | uniq -c | sort -rn`
- one dir returns a directory listing (200) and serves its access.log/error.log directly on request, that's the exposed path

## 24 hours of Le Zook (Hard)
Challenge: This small network contains systems that are running some services that aren't allowed by IT. Can you use the supplied network logs to figure out if these are benign or deserve some additional investigation and forensics? While the labels used for each field aren't very descriptive, they are at least consistent across the logs.
Artifact(s): pi_ub2004_64.tar.gz (live instance)

Notes:
- `tar -xzf pi_ub2004_64.tar.gz` -> `pi_ub2004_64/` with 24 hourly rotations of each Zeek log (conn, dns, dhcp, http, ssl, ntp, files, weird, x509, software, known_services, ...)
- box has no `find` and no `jq`, so everything is `cat`/`grep -o`/`sort`/`uniq`
- logs are JSON with field names obfuscated to f1, f2, ... but consistent across logs. mapped them by eye:
    - f1 = ts, f7 = log type, f9 = uid, f10/f11 = orig_h/orig_p, f12/f13 = resp_h/resp_p
    - http: f79 = method, f80 = host, f81 = uri, f84 = user_agent
    - dhcp: f32 = mac, f33 = host_name, f34 = client_fqdn, f35 = domain, f36 = assigned_addr
    - dns: f42 = query, f54 = answers
    - ssl: f132 = server_name; x509: f173 = subject
    - weird: f123 = name
- quick header dump per log type:
    - `for t in $(ls | cut -d. -f1 | sort -u); do f=$(ls $t.*.log | head -1); echo "=== $t"; grep -v '^#' $f | head -1; done`

Q1: Unencrypted web server, service named by the first word of the URI path?
- http.log on port 80 shows a `GET /<service>/data/...`, the first path component names the ADS-B / dump1090-style receiver web UI

Q2: IPv4 that service runs on?
- resp_h on those same http lines, cross-checked against known_services (port 80 / HTTP)

Q3: External IPv4 providing NTP to the network?
- `cat ntp.*.log | grep -o '"f12": "[^"]*"' | sort | uniq -c`
- one external resp_h dominates, that's it

Q4: From Q3, what Linux variant is the web host running?
- the NTP server's /8 belongs to Canonical's pool, ssl also surfaces a `motd.*` host and the tarball name itself hints the distro, so whois the NTP IP and connect the dots

Q5: Web browser software used on 10.0.0.111?
- software.log carries an `HTTP::BROWSER` entry for that host, read the product name off its User-Agent

Q6: Firmware-update server DNS name (over an encrypted connection)?
- the encrypted update check leaves a TLS trail, so list the SNIs and the matching cert subjects and find the pair tied to the update traffic
    - `cat ssl.*.log | grep -o '"f132": "[^"]*"' | sort | uniq -c`, then cross-check the x509 subject CNs (f173)
- the CN that lines up with that SNI is the server's DNS name

Q7: Device other than the macbook advertising RAOP over TCP? (format: model, product)
- RAOP = AirPlay audio, mDNS service `_raop._tcp.local`
    - `cat dns.*.log | grep -i raop | grep -o '"f42": "[^"]*"' | sort -u`
- two instances advertise, one is the macbook, the other is the device you want
- pull that device's TXT records and read the `model=` fields:
    - `cat dns.*.log | grep -i '<device label>' | grep -o 'TXT [0-9]* [a-z]*=[^ "]*' | sort -u`
- the two `model=` values decode to an internal board ID plus an Apple product identifier

Q8: One system wants to keep a DNS name (not a hostname), what org? (format: domain.tld)
- only one DHCP client sent a client FQDN (f34):
    - `cat dhcp.*.log | grep -o '"f3[2-9]": "[^"]*"' | sort | uniq -c`
- that FQDN's parent domain tells you the organization it came from

Q9: MAC of a network-infrastructure device that requested a DHCP lease?
- skim the dhcp hostnames, one of them is a managed-switch model string (a TP-Link 16-port switch)
- `cat dhcp.*.log | grep '<switch model>'` -> its REQUEST line carries the MAC

Q10: Zeek flagged an anomaly on the very first exchange, which Microsoft protocol suite does the exposed API belong to? (exact protocol from the logs)
- weird.log has only 2 lines, same uid (`possible_split_routing` + `data_before_established`; conn history `SAD`, so Zeek missed the handshake)
- `grep -h '<uid>' conn.*.log http.*.log files.*.log`
    - it's a SOAP request (`application/soap+xml`) to a web-service endpoint exposed on one of the devices
    - the request's User-Agent names the Microsoft API suite behind that service
- map that User-Agent string to the protocol suite it belongs to
