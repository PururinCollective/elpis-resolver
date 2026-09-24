do performance test or benchmark after all the fix, test against various popular domain:

1. forums.linuxmint.com
2. Epic Games Launcher
3. Taobao
4. Shopee (MY/SG/ID)
5. Ubisoft Connect
6. EA
7. Steam
8. Google
9. Cloudflare
10. YouTube
11. Telegram Web (sometime this have very slow loading, IPvFoo show domain is resolved, but some are not)
12. Whatsapp
13. Pixiv
14. Apple
15. Microsoft (and it's Windows Updates domain)
16. Discord
17. Lowyat.net
18. GitHub
19. Asus/MSI/Acer/Gigabyte/etc...
20. and more you can think of

if in all well, bump version to 1.1.16 or v2.0 stable and update CHANGELOG

---

I'll extend the existing site test with all the services you listed and some more. Each site is timed cold (fresh resolver) and warm, against 1.1.1.1 as a reference, with every answer checked for agreement. First, the current script:

I'll build a broader benchmark of ~30 site groups (including streaming, social, games, Malaysian banks/government, and hardware vendors), querying each site's known hosts for A, AAAA, and HTTPS records like a browser would. First, I'll check which nameservers serve Telegram, since that's where the slow-loading issue points.

Telegram's zones are on Google Cloud DNS, which is well-behaved, so the Telegram hosts get individual timings as a separate step. Writing the benchmark:

I'll benchmark the current tree against 1.1.15 (cold and warm, plus 1.1.1.1) to confirm the fixes are cost-free, but first I need to rebuild my 1.1.15 scratch copy as release since it's currently an ASan build.

Both builds resolved everything except two Malaysian domains: `www.hasil.gov.my` fails with SERVFAIL due to a missing DS record, and `www.cimb.com.my` HTTPS times out on cold lookups only. I'll now run 1.1.1.1 and the 1.1.15 build for comparison before investigating these two further.

Both issues are explained: cimb.com.my's HTTPS failure is an upstream problem shared with 1.1.1.1, while hasil.gov.my's A record failure is a genuine Elpis bug that predates this session. I'll start investigating the hasil.gov.my issue by tracing the DS lookup chain for eservices.hasil.gov.my.

Found the cause: `eservices.hasil.gov.my` is a CNAME to Microsoft's App Proxy rather than having its own DS record, which confuses the validator's DNSSEC chain-of-trust lookup. I'll now check which zone actually signed the final A record to understand why the walk descends that far.

The final A record for www.eservices.hasil.gov.my has no signature despite sitting under the signed hasil.gov.my zone. I'll check whether it's legitimately delegated to an unsigned child zone below the CNAME.

I've confirmed the validator bug: it fails to recognize a CNAME as proof that a name isn't a zone cut during the DS walk, causing it to mishandle signed zones like hasil.gov.my. The fix is to treat a CNAME response as a signal to skip past that label using the parent's keys, which is fail-safe since forged CNAMEs would just push validation to fail as bogus rather than falsely appear insecure—now checking the lookup code near the earlier NXDOMAIN fallback to implement this.

I'll add the CNAME case in both places: the DS lookup accepts a cached CNAME at that name as its answer, and the descent treats it as "not a cut" and keeps walking with the same keys.

Fixed — those two records now resolve insecurely without AD, matching 1.1.1.1, and hasil.gov.my keeps AD intact with no logging. Now checking `www.cimb.com.my` HTTPS, since Elpis took 5.3s to hit SERVFAIL versus 1.1.1.1's 138ms, by examining how CIMB's nameservers handle that query type.

Confirmed: three of CIMB's six nameservers don't respond at all, and the other three drop HTTPS-type queries silently while still answering A/AAAA quickly, which explains the resolution failure. Now I'll time Elpis on a fresh instance to see how it handles this, including whether the dropped HTTPS queries make it hesitant on subsequent ordinary A lookups.

Found a real caching gap: HTTPS record failures for cimb.com.my aren't cached (violating RFC 9520), causing retries to get slower each time, though A/AAAA/MX/TXT lookups stay unaffected. Before fixing this, I'll check the Telegram rows from the cold run, since their 190ms median could reflect the same slow-record-type pattern behind your Telegram Web loading issue.

All 93 Telegram DNS queries succeeded and matched 1.1.1.1, just consistently around 190 ms on first lookup, likely due to network distance. I'll check the round trip time to Telegram's Google Cloud DNS servers from this VM.

Telegram's nameservers sit close by (7-80 ms) but are hosted under googledomains.com without glue records, meaning the first query must resolve those nameserver names before proceeding, likely explaining the 190 ms median. I'll verify this cost is a one-time setup per zone rather than a recurring overhead.

Each new telegram.org name costs ~163ms while telesco.pe is fast, suggesting Elpis keeps querying the distant ns-cloud-b1 server instead of the 7ms ones, possibly twice per name due to QNAME minimisation. I'll trace outbound packets with strace to confirm which server each query actually hits.

The pattern repeats under trace: about 165 ms for each new name. Reading which servers those queries went to, from the mark onward:

Found the root cause: Telegram queries always hit the slow ns-cloud-b1 (never the fast b2/b4) and QNAME minimisation redundantly re-probes the parent domain for every new hostname, adding ~160ms instead of ~8ms per lookup. I'll stop the stray test process and dig into how glueless nameserver resolution and server selection work.

Found the root cause: `TS_NSADDR` resolves only one nameless nameserver's address and caches the delegation with just that server, so glueless zones get stuck on whichever server was found first regardless of latency. I'll fix this by enriching cached delegations with already-known addresses and kicking off deduplicated, capped background lookups for the rest, then verify the sweep threshold correctly triggers probes when a server responds slowly (e.g. 80ms).

Unmeasured servers default to a 376 ms guess, and the sweep automatically probes alternatives once the best-known server hits 40 ms or slower — so once b2–b4 have addresses, they'll get found without extra logic. I'll write in the addresses now.

Status: the hasil fix is in. The benchmark showed that Elpis sends all Telegram queries to the one far nameserver, and I'm now writing the fix so it learns every nameserver's address.

Build succeeded with all 373 tests passing. Now re-running the Telegram sequence on a fresh instance to verify names update correctly across the initial load, immediate additions, and delayed additions after background lookups complete.

The fix works—new names now resolve in 17ms (down from ~164ms) and root-level telegram.org names in 7-9ms. The remaining 17ms overhead comes from a redundant QNAME-minimisation probe under web.telegram.org, which RFC 9156 allows skipping since the cached answer already proves it's not a zone cut, so I'll dig into the minimisation code to fix that.

I'll implement this: skip the probe when the cache shows the answer was already resolved directly by the zone in question, saving a round trip without changing the outcome.

New Telegram lookups now resolve in 7–9 ms instead of ~164 ms, with all 373 tests passing. Next I'll implement RFC 9520 failure caching so repeated queries for broken names get immediate SERVFAIL, starting by checking how finished answers reach the message cache and whether SERVFAILs are currently excluded.

I see finished answers get cached by name, type, and DO/CD flags. I'll now check the entry conditions to find where SERVFAIL is excluded and how cached rcodes are served.

I'll add a small failure cache per RFC 9520 that remembers SERVFAIL results (keyed by name/type/CD bit, backing off 5s to 60s) without touching the message cache, excluding overload refusals. Now reviewing the query path around cache lookups, overload handling, and error reply construction.

EDE 13 is already defined. Checking how the server attaches an EDE code to a reply, so `reply_error` can take one:

I'll add an EDE parameter to `reply_error` and keep the failure table in `server.c`, since queries enter and responses leave via `elpis_task_respond` on the same worker thread. Now checking where SERVFAIL replies are counted and whether `elpis_name_hash` already handles case folding.

The name hash already folds case. Writing the failure cache in `server.c`:

`elpis_task_respond` comes earlier in the file than the new code, so it needs a forward declaration beside the existing ones at the top:

Build is clean with all 373 tests passing. Now retesting CIMB behavior: the first HTTPS query should fail slowly, subsequent ones should get an immediate cached SERVFAIL for 5s, then re-resolve and hold for 10s, while A/AAAA lookups for the same name remain unaffected.

The core caching logic works, but I found the failure table isn't shared across SO_REUSEPORT workers, letting retries slip through per-worker gaps. I'll make the table shared using a lock-free seqlock design so concurrent access at worst triggers one extra resolve, never a false SERVFAIL.

All six repeats across the 4 workers returned the cached SERVFAIL immediately and again 3.5s later, confirming the 5s hold behavior. Now I'll rerun the full benchmark on the final build (cold then warm) and compare against the first run and 1.1.1.1, including a per-query agreement check.

Elpis matches 1.1.1.1 on 1,218 of 1,221 queries (the differences are benign CDN/SERVFAIL cases) and is much faster when warm, though cold-cache comparisons aren't fair since 1.1.1.1's cache is already warm. Now I'll check the AD flag discrepancy (76 vs 69) to confirm Elpis isn't over-claiming DNSSEC validation, listing each disagreement.

I've identified seven cases where Elpis returned AD but 1.1.1.1 didn't, involving Outlook records and empty-answer responses for office.com and mysejahtera.gov.my. Since AD on an empty answer is only valid if the denial proof truly checks out, I'll verify each with an independent validator like BIND's delv and inspect Elpis's actual responses.

The Outlook/Office discrepancies were just TTL-related noise—Elpis is correct there. But `www.mysejahtera.gov.my` is a genuine bug: it's an NXDOMAIN backed by an opt-out NSEC3 record, meaning RFC 5155 requires AD to stay unset, yet Elpis sets it anyway. I'll confirm with `delv` and then track down where Elpis decides AD for denial responses.

I've confirmed that RFC 5155 §9.2 forbids setting AD when opt-out NSEC3 covers the next-closer name, which Unbound and 1.1.1.1 respect but Elpis overclaims. Now I'll dig into Elpis's NSEC3 denial code to find where it sets that verdict.

I'll add a distinct return value (2) for cases proven only via an opt-out span, keeping existing callers unaffected since they just treat results as true/false. Next I'll check `check_denial`, the place that decides AD, to see how it can distinguish this new case.

I'll extend `check_denial`/`tally` to propagate a third value: proof via opt-out span means INSECURE (answer served without AD), applying the same treatment to DS "no data" cases per RFC 5155 §8.6 and §9.2.

Negative answers now conform to RFC 5155, with opt-out zones (gov.my, .com) correctly showing no AD and non-opt-out zones showing AD, matching 1.1.1.1's behavior. Since my last test command ran after the instance stopped, I'll rerun the full DNSSEC matrix against the baseline, including a consistency check on .com NXDOMAIN via 1.1.1.1.

The matrix confirms the fix: `nonexistent-ID.com` now correctly drops the AD flag, matching 1.1.1.1's behavior on that opt-out span. Now I'll run the sanitizer pass over today's additions—cold/warm site benchmarks on ASan/UBSan, the failure-cache path via CIMB, and SIGINT handling with in-flight lookups.

Sanitizer runs are clean with zero ASan/UBSan reports across the full benchmark, failure-cache path, and shutdown with in-flight lookups. Now I'll commit the fixes as separate commits, splitting the two unrelated fixes in `src/dnssec.c` into their own hunks.

Hunks 1 and 5 are the CNAME fix; hunks 2–4 are the opt-out AD. Committing in four parts:

Since the forward-zone change breaks previously working configs, this qualifies as a major version bump under your rule — I'll tag it 2.0.0 instead of 1.1.16. Now checking where else the version number appears beyond the Makefile, README, and changelog.

I'll update the version references in the Makefile and README, then add a 2.0.0 changelog section covering the release summary, the failure cache under Added, and the four new fixes under Fixed.

Now I'll do a final check: rebuild everything with the updated version stamp, run unit tests, do the clang build, then a quick test run of the 2.0.0 binary.

I ran the benchmark, fixed what it turned up, and cut **2.0.0**. It's committed (c7eb09e) but not pushed, with 9 commits waiting.

**Benchmark:** 28 groups of services, 1,221 lookups. Every host of a site was asked A, AAAA and HTTPS at once, as a browser does, and each answer was compared with 1.1.1.1.

| | p50 | p90 | p99 |
|---|---|---|---|
| Elpis, warm cache | **0.6 ms** | 1.1 ms | 1.5 ms |
| Elpis, cold (real recursion from empty) | 82 ms | 269 ms | 709 ms |
| 1.1.1.1 from this VM | 4.2 ms | 15.5 ms | 170 ms |

Elpis agreed with 1.1.1.1 on 1,218 of 1,221 answers. Two of the differences were CDNs answering by location. In the third, `www.pbebank.com` AAAA, Elpis answered and 1.1.1.1 gave SERVFAIL.

**What it found, now fixed:**
- **`www.hasil.gov.my` (LHDN) failed with SERVFAIL**, on 1.1.15 too. An unusual CNAME in the middle of the site's signed chain stopped the security check. It now resolves, like it does on 1.1.1.1.
- **Telegram:** every new Telegram hostname took about 164 ms. Telegram's DNS is on Google Cloud DNS, which has four servers; Elpis only ever used the first one it looked up, 80 ms away, while two others are 7 ms away. It also sent an unneeded extra query per name. Elpis now learns all of a zone's servers in the background and skips queries its cache already answers. **New Telegram names now take 7–9 ms.** This affects most sites hosted on Google Cloud DNS, Route 53 or Azure DNS, not just Telegram.
- **Failures weren't remembered.** CIMB's DNS servers never answer the HTTPS record type that browsers ask for on every site, so each retry spent another 5–10 s failing. Failures are now held for 5 s at first, up to 60 s if the name keeps failing, and repeat queries get an instant SERVFAIL. This follows RFC 9520.
- **AD was set where the RFC forbids it:** on "name does not exist" answers from zones using an NSEC3 feature called opt-out, including every nonexistent `.com` and `gov.my` name. Unbound and 1.1.1.1 correctly leave it off, and now Elpis does too.

**Checks on the final build:** 373 unit tests pass, and the DNSSEC test set is unchanged apart from that intended opt-out AD fix. ASan/UBSan reported nothing across the benchmark and a shutdown with 30 lookups in flight, and the build is warning-free under gcc and clang.

**Why 2.0.0 rather than 1.1.16:** your changelog says the major number changes when a config that worked stops working. One does: an instance that forwards everything (`forward-zone: .`) to an upstream serving a private zone now needs an extra line for that zone, e.g. `forward-zone: corp 10.0.0.53`. The changelog lists it under **Changed**. If you set up the XLAT VM that way and your main Elpis serves private zones, add those lines there.

**On Telegram Web:** the slow DNS lookups were real and are fixed, but they cost about a sixth of a second per hostname, not whole seconds. IPvFoo also leaves connections without an address when the browser reuses an existing connection or opens a WebSocket. If Telegram is still slow after this, the cause is likely outside DNS.

To publish:
```bash
git push
```
