# DNSSEC

Validation, the algorithms implemented, and the standards followed.

## Validation

Elpis validates against the published IANA root anchors, with RSA
(1024–4096), ECDSA P-256/P-384, Ed25519 and **ML-DSA-44/65/87** (FIPS 204)
implemented from scratch. Denial of existence is checked with NSEC and NSEC3,
including opt-out and the RFC 9276 iteration cap. Data that fails validation
gets SERVFAIL and an extended DNS error — it is never handed to the client.

Every RRset is judged against the zone that actually served it, which matters
most for the ones that arrive with no signature at all. A CNAME leaving a
signed zone for an unsigned one is ordinary — half the CDN-hosted internet
looks like that — and the answer is insecure, not forged. An RRset whose own
zone *is* signed arriving without its signature is the stripping attack, and
that is refused with `RRSIGs Missing`. The two are told apart by provenance:
the resolver records which zone produced each record as it accepts it, so the
question is answered from fact rather than inferred from whatever else happens
to share the message.

## Query authentication

DNS cookies (RFC 7873/9018) in both directions:
outbound queries carry one so an off-path attacker cannot forge a reply, and
incoming cookies are verified — with `require-cookie` on, a client echoing a
cookie that does not check out gets BADCOOKIE and a fresh one rather than an
answer. Responses are also matched on transaction ID, source port, the exact
0x20 casing of the question, and the server address.

## Standards


Core: 1034, 1035, 2181, 2308, 3596, 3597, 4343, 5452, 6891, 7766, 9619
Security: 4033–4035, 4470, 5155, 6605, 6840, 7873, 8080, 8624, 8914, 9018,
9276, 9715
Behaviour: 6052, 6147, 6303, 6672, 6761, 6762, 7686, 8020, 8482, 8767, 9156,
9210, 9471, 9520

ML-DSA verification follows FIPS 204, and the DNSSEC side follows
`draft-westerbaan-dnssec-mldsa`, which gives ML-DSA-44 algorithm number 18 —
the number the public test zones sign with, and the default here. IANA has not
made it final and the draft assigns nothing to the 65 and 87 parameter sets, so
all three remain settings rather than constants: point `mldsa44-algorithm` at
whatever your zone publishes. The draft's worked example is in the test suite,
so the key tag, the DS digest and a real RRSIG are checked on every build.

---

[Caching](caching.md) · [Configuration](configuration.md) · [Internals](internals.md) · [Troubleshooting](troubleshooting.md)
