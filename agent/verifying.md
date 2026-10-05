# ✅ Verifying a change

What "done" means here. Run what applies; say what you ran and what you didn't.

## 🧪 Always

```bash
make                       # no warnings
make test                  # all pass (677 at 2.4.0)
```

## 🔬 For anything in C

```bash
# sanitizers (the test binary, not just bin/elpis)
make clean && make OPT="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
     -fno-sanitize-recover=undefined" LDFLAGS="-fsanitize=address,undefined" bin/elpis-test
./bin/elpis-test

# a second compiler
make clean && make CC=clang bin/elpis bin/elpis-test && ./bin/elpis-test

# the portable build, no x86 kernels (fewer checks: the AES-NI ones are skipped)
make clean && make UNAME_M=generic bin/elpis-test && ./bin/elpis-test

make clean && make         # back to normal before you finish
```

## 🌀 For parsers, crypto or TLS

```bash
make fuzz
cd bin && mkdir -p corpus-tls && UBSAN_OPTIONS=halt_on_error=1 \
  ./fuzz-tls -max_total_time=300 -jobs=4 -workers=4 corpus-tls/
grep -h "runtime error\|ERROR: AddressSanitizer" fuzz-*.log    # expect nothing
```

New crypto vectors: check them against Python's `cryptography` (or OpenSSL)
**before** freezing them in a test. A misremembered RFC vector has happened.

## 🌐 For resolver behaviour: a live run

Run a scratch instance on high ports, never on the user's real ports or config:

```
listen: 127.0.0.1@5399
access-control: 127.0.0.0/8 allow
stop-systemd-resolved: no
webgui: yes
webgui-listen: 127.0.0.1@8099
webgui-password: <a throwaway test value>
```

```bash
./bin/elpis -t -c /tmp/x/test.conf          # check it
./bin/elpis -d -c /tmp/x/test.conf          # run it (in the background)
dig @127.0.0.1 -p 5399 example.com A
```

The status API needs a login: `POST /api/login` with `user=...&pass=...`
(form-encoded, keep the cookie), then `GET /api/status`.

> [!CAUTION]
> Stop it **by PID**. `pkill -f <pattern>` also matches the shell running the
> pkill, and kills it. And check `ps` first: the user may run real Elpis
> instances on the same machine.

### Regression list

After changes to resolution, validation or server selection, resolve these
cold (A, AAAA and HTTPS at once per host) and compare status and
answer-presence with 1.1.1.1:

| site | why it's on the list |
|---|---|
| forums.linuxmint.com | an insecure child answered by its signed parent's server |
| Epic Games Launcher hosts | dozens of names behind Route 53, unsigned CNAMEs into signed `cdn.cloudflare.net` |
| Taobao (`taobao.com`, `alicdn.com`, `mmstat.com`) | many hosts, far-away authorities |
| Shopee MY / SG / ID | many hosts, SEA authorities |

<sub>Shopee shows an anti-bot captcha to automated browsers: that's not a DNS
failure. CDNs answering with different addresses than 1.1.1.1 is expected;
compare status and whether an answer came back.</sub>

### Useful outside checks

| check | how |
|---|---|
| DNSSEC matrix | dnscheck.tools test names (alg 13/14/15/18 × valid, badsig, expiredsig, nosig) |
| post-quantum, root sentinels | dnstest.dev names, compared with 1.1.1.1 |
| ECS | `dig @127.0.0.1 -p 5399 o-o.myaddr.l.google.com TXT +subnet=...` |
| DoT | `make tls-probe && bin/elpis-tls-probe 1.1.1.1 example.com A`; live, Facebook's and Wikimedia's authoritative servers and b.root-servers.net speak DoT |

## 📋 Before you say it's done

- [ ] `make test` passes; count stated
- [ ] gcc and clang, no warnings
- [ ] ASan/UBSan clean, if C changed
- [ ] docs and `elpis.conf` updated, if behaviour or settings changed
- [ ] `CHANGELOG.md` `## Unreleased` entry, if users would notice
- [ ] nothing in AGENTS.md's protected list touched, or touched only as it allows
