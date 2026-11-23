# Forensics

## Fuzzy (Hard)
Artifact(s): message1.png, message2.png
Challenge: We intercepted some data from Liber8tion. They slipped up and we got a drop on some messages last year, but they've since started redacting the sensitive info. Can you unredact the latest key we got from them?

Q1: What Google font is used in the example message?
- match the typeface from the example message with a font matcher
- used Adobe's match-font uploader: https://fonts.adobe.com/fonts/vs/upload

Q2: What is the flag in the blurred message?
- the redaction is a blur, not a solid box, so the underlying text is still there to recover
- read the flag off the deblurred message (see Q3 for the deblur)

Q3: What is the SSH public key in the blurred message? (Starts with ssh-ed25519 and does not need the flag at the end)
- blur is a lossy but recoverable transform, so you can walk it back
- deblur tool: https://unblurimage.pro/
- status: didn't finish this one, had the tool but never got a clean enough read to pull the ssh-ed25519 key

## Browsing (Medium)
Challenge: An intern seems to be browsing to suspicious sites. We've exported some of their browser data. Can you look through it and answer the questions? sqlite3 is available on the box.
Artifact(s): places.sqlite

Setup:
- `sqlite3 places.sqlite ".tables"`
- moz_places + moz_historyvisits -> Firefox history (moz_places = URL + title, moz_historyvisits = each visit, join on place_id)
- Firefox timestamps are PRTime (microseconds since 1970), so divide by 1000000 for unixepoch

Timeline (the one query that drives everything):
- `sqlite3 places.sqlite "SELECT datetime(h.visit_date/1000000,'unixepoch'), p.url, p.title FROM moz_historyvisits h JOIN moz_places p ON h.place_id=p.id ORDER BY h.visit_date;"`
- reading that dump in order rebuilds the whole session (the q= params, the repo/download/support pages, the final subreddit)

Where to read each one off:
- Q1 first search query -> q= param on the first row
- Q2 software likely downloaded -> moz_annos (downloads) is empty, so infer from history: the /download page hit right after the mining guide
- Q3 GitHub repo visited -> the github.com row (owner/repo is in the path)
- Q4 support domain -> the support.* subdomain row
- Q5 subreddit after the Q4 domain -> next row after that support visit
- Q6 minutes between first and last activity -> diff the two timestamps, round down
- Q7 benchmark resource URL -> the /benchmark row
- Q8 unique base domains (excluding subdomains):
    - `sqlite3 places.sqlite "SELECT DISTINCT host FROM moz_origins;"`
    - collapse subdomains to their base (a support. and www. of the same site count once)
    - drop any origin that's in moz_origins but never actually visited (Firefox default bookmarks)
- Q9 timestamp of first activity -> first row's datetime (UTC)
- Q10 final search query -> last q= param
