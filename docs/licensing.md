# 🔏 Signed licences

`edition:` in the config file is self-declared: anyone can write `commercial`
in their own copy, and nothing checks. That's the right amount of mechanism for
labelling your own fleet, and not enough for a claim somebody else should
believe.

**A licence is the same claim, carried by an Ed25519 signature** from whoever
issues licences for a build, so it can be checked without asking them.

```bash
nslookup -q=txt elpis.sakurako.oomuro 127.0.0.1
```

```
"elpis=1.0.0" "edition=commercial" "build=e992e1460fb5"
"licence=verified" "licensed-to=Example ISP, AS64500"
"serial=1001" "expires=2027-09-21"
```

Without a licence the same resolver says `edition=commercial` and nothing more.

> [!IMPORTANT]
> **The absence of `licence=verified` is the whole signal.**

```
   issuer (you)                                a resolver, anywhere
 ┌──────────────────────┐   licence: line    ┌─────────────────────────────┐
 │ issuer.key  (secret) │ ─────────────────► │ elpis.conf                  │
 │ elpis-licence issue  │                    │   checks the signature with │
 └──────────┬───────────┘                    │   the issuer key built in   │
            │ public half                    └─────────────────────────────┘
            ▼                                              ▲
   include/elpis/licence.h  ──── built into every binary ──┘
```

## 📏 What this does and does not do

| ✅ it does | ❌ it does not |
|---|---|
| Stop an operator claiming an edition by editing a text file, the only thing otherwise standing between "community" and "commercial". A real threshold, and the one almost everybody is on the honest side of. | Stop someone who patches the binary. A modified build prints whatever its author wants, including a forged `licence=verified`. |

<sub>No software can attest to its own integrity to a remote party. Remote
attestation of an untrusted binary isn't something signatures can give you,
and no amount of cleverness here changes that.</sub>

What the signature is genuinely good for:

- **Offline verification.** Given a config file, `elpis-licence verify` says
  whether that licence is real, without contacting anybody.
- **Raising the bar from "type a word" to "patch and rebuild".** Different
  people are willing to do those two things.
- **Expiry and identity.** A self-declared field can't say who, or until when.

> [!NOTE]
> **It is not licence enforcement, and Elpis has none.** A licence never
> changes how a query is answered. An expired one is logged and reported and
> nothing stops working: a resolver that stopped resolving because a date
> passed would be a far worse failure than anything this protects against.

## 🔓 What a licence unlocks

| setting | without a licence |
|---|---|
| `identity-name:` | ignored with a warning; the probe answers at its default name |

Everything else works the same either way. Nothing is withheld that affects
whether the resolver answers correctly.

<sub>A lapsed licence keeps what it unlocked. Expiry already doesn't stop the
resolver resolving, and quietly moving a name that somebody's monitoring points
at would be a worse surprise than the warning in the log.</sub>

## 📝 Issuing licences

The tool is built separately and never installed:

```bash
make licence-tool
```

It's the only thing in the tree that signs. **`bin/elpis` contains no signing
code at all**: `ELPIS_ED25519_SIGN` is defined for this tool and the test
binary, and nowhere else.

### One-time setup

```bash
./bin/elpis-licence keygen issuer.key
```

That writes the private key with mode 0600 and prints the public half. Put the
public half in [include/elpis/licence.h](../include/elpis/licence.h):

```c
#define ELPIS_LICENCE_ISSUER "6cd740f1...dd6315"
```

and rebuild the binaries you distribute.

| to set the issuer key | |
|---|---|
| for one build | `make LICENCE_ISSUER=<hex>` |
| for every build of your tree | `LICENCE_ISSUER = 6cd740f1...dd6315` in `local.mk` |

<sub>Git ignores `local.mk`, and unlike your shell's environment it still
reaches `sudo make install` and `contrib/elpis-update.sh` (see
[keeping build settings in local.mk](COMPILING.md#keeping-them-in-localmk)).</sub>

> [!CAUTION]
> **`issuer.key` is the whole system.** Anyone holding it can mint licences
> every binary you've shipped will believe, and the only remedy is a new key,
> which invalidates every licence already issued. Keep it off the build machine,
> out of the repository, and backed up somewhere you can still reach in a year.

<sub>A stock build has no issuer key and rejects every licence, saying so
plainly. That's correct for a source tree that doesn't belong to an
issuer.</sub>

### Issuing one

```bash
./bin/elpis-licence issue --key issuer.key \
    --org "Example ISP, AS64500" --edition commercial --days 365 --serial 1001
```

```
commercial licence for "Example ISP, AS64500", serial 1001, expires 2027-09-21
add this line to elpis.conf:

licence: elpis1.AQEAAAPparF1_GySqXwURXhhbXBsZSBJU1AsIEFTNjQ1MDA.5oQtWOS5ft8...
```

| option | |
|---|---|
| `--edition` | one of `commercial`, `community`, `homelab`, `evaluation` |
| `--perpetual` | **how to issue one that never expires**, rather than a very large `--days`. It records no expiry at all, so the probe and the status page say `never`, not a date a century out somebody then has to reason about |
| `--days -N` | back-dates the expiry, which is how you see what a customer with a lapsed licence sees. Beyond a thousand years either way it's refused, pointing at `--perpetual` |

### Checking one

```bash
./bin/elpis-licence verify "elpis1....."
```

Exits 0 when the signature is good, 1 when it isn't, and prints the claims
either way.

## 🎫 The token

One line, safe to paste, small enough for a single DNS character-string:

```
elpis1.<base64url payload>.<base64url signature>
```

The payload is fixed-layout binary rather than JSON, which keeps a typical
licence near 140 characters:

| offset | size | field |
|---|---|---|
| 0 | 1 | format version |
| 1 | 1 | edition |
| 2 | 4 | serial |
| 6 | 8 | issued, signed unix seconds |
| 14 | 8 | expires, signed unix seconds, 0 = perpetual |
| 22 | 1 | length of org |
| 23 | N | org, UTF-8 |

<sub>**Why 64-bit dates?** Unix seconds in 32 bits run out in 2106, which sounds
distant until someone issues a hundred-year licence: `--days 36500` lands past
the wrap and comes back as 1990. A date field that can silently travel
backwards is worse to ship than eleven extra characters of token.</sub>

**What's signed** is `elpis-licence-v1` followed by those bytes.

<sub>The prefix is domain separation: a signature made for a licence can't be
replayed as a signature over anything else this project ever signs, and vice
versa.</sub>

## 🙈 What is never published

**The token itself.** The identity probe and the status page report the
*claims* (verified, org, serial, expiry), never the token: echoing it would let
anyone who can query the resolver lift the licence and paste it into their own
config.

> [!TIP]
> For the same reason, put the probe behind an access-control list you actually
> mean, or move it to a private name with `identity-name:`. See
> [asking a resolver what it is](configuration.md#-asking-a-resolver-what-it-is).

## 🔬 The signing code

Ed25519 signing lives in `src/crypto/ed25519.c` behind
`#ifdef ELPIS_ED25519_SIGN`, next to the verification it mirrors. It's compiled
into the licence tool and the test binary, **not into the resolver**, which has
no business holding a signing routine.

<sub>It's checked against all three RFC 8032 section 7.1 vectors in both
directions (public key derived from the secret, and signature byte-identical to
the published one), rather than only against our own verifier, which would pass
happily if both halves were wrong in the same way.</sub>

---

<sub>[README](../README.md) · [Compiling](COMPILING.md) · [Configuration](configuration.md) · [Caching](caching.md) · [DNSSEC](dnssec.md) · [Status page](status-page.md) · [Troubleshooting](troubleshooting.md) · [Quirks](quirks.md) · [Internals](internals.md)</sub>
