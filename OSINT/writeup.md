# OSINT

## Wordsmithing (Medium)
Challenge: One of our support reps took off on a hiking vacation. We need to find her to ask her a question, but she only left this itinerary: 1 locals.attract.requirement, 2 breakfast, 3 take a walk, 4 hugged.mastermind.pleasing. Can you help us locate her?

Note: this is a `what3words` challenge, each three-word group maps to a 3m x 3m square. Plug them into https://what3words.com for coordinates.

Q1: What restaurant is nearest ///locals.attract.requirement ?
- resolve the what3words address, then look at nearby restaurants on a map

Q2: She's headed to ///hugged.mastermind.pleasing; what mountain is this on?
- resolve the second address and ID the mountain at that point

Q3: On what trail is she hiking? (Answer format: the name of the trail found near BOTH the points in Q1 and Q2)
- look for a single long-distance trail that passes near both points

Q4: What's the great circle distance between these two points? Use the Haversine formula, round to the nearest km. GPS lat/long only, ignore altitude.
- Haversine:
    - `a = sin^2(dLat/2) + cos(lat1)*cos(lat2)*sin^2(dLon/2)`
    - `c = 2 * atan2(sqrt(a), sqrt(1-a))`
    - `d = R * c`   with R = 6371 km
- pull lat/long for each what3words point, convert the deltas to radians, plug in, compute d

Q5: If she hiked the entire official trail, how far would she walk? (km, round to nearest 10km)
- look up the official end-to-end length of the Q3 trail, convert to km

## Barcode (Medium)
Artifact(s): barcode.png
Challenge: Someone taped a water-damaged barcode sticker to a friend's laptop case and no further context was provided. Can you help us decode it?

Notes:
- 13 digits + 1 check digit = 14 digits, all numeric, which matches a library barcode
- Codabar is what libraries standardize on for a 14-digit all-numeric string
- ref: https://en.wikipedia.org/wiki/Codabar

Q1: What is the last digit of this barcode (fully obscured by the damage)?
- the last digit is a check digit over the other 13, which you can read
- assuming Codabar, compute it with the Luhn algorithm over the 13 known digits

Q2: What institution was the barcode likely issued by? (include the abbreviated US state, e.g. InstitutionName, NY)
- Codabar layout: barcode type, then a 4-digit institution code, then the item number, check digit last
- take the 4-digit institution code and look it up in state library barcode registries
- started with Maine's registry (https://www.maineinfonet.org/mainecat/maine-barcode-symbol-registry/), no match
- tried New Hampshire next since the previous challenge pointed to NH; the NH State Library publishes a barcode/identifier list: https://www.nhsl.dncr.nh.gov/sites/g/files/ehbemt726/files/inline-documents/barcodes-identifiers.pdf
- cross-reference the 4-digit code there to get the institution and state
