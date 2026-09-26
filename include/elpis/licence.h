/*
 * elpis/licence.h -- signed deployment licences.
 *
 * `edition:` in the config file is self-declared: anyone can write
 * "commercial" in their own copy.  That is the right amount of mechanism for
 * labelling a fleet, and not enough for a claim somebody else should believe.
 * A licence is the same claim carried by an Ed25519 signature from whoever
 * issues licences for this build, so it can be checked without asking them.
 *
 * What this does and does not defend against is worth being exact about.  It
 * stops an operator from making the claim by editing a text file, which is the
 * only thing standing between "community" and "commercial" today.  It does not
 * stop one who patches the binary: no software can attest to its own integrity
 * to a remote party, and a modified build can print whatever it likes.  The
 * signature is what makes an unmodified resolver's answer worth reading, and
 * what lets a licence be verified offline from a config file alone.
 */
#ifndef ELPIS_LICENCE_H
#define ELPIS_LICENCE_H

#include "elpis/common.h"

/*
 * The Ed25519 public key licences for this build are signed with, as 64 hex
 * characters.  Empty by default: a build with no issuer key rejects every
 * licence, which is the honest behaviour for a source tree that does not
 * belong to an issuer.
 *
 * To issue licences, generate a key with `elpis-licence keygen`, keep the
 * private half somewhere the build machine cannot reach, and paste the public
 * half here before building the binaries you distribute.  Changing it
 * invalidates every licence signed with the old key.
 */
#ifndef ELPIS_LICENCE_ISSUER
#define ELPIS_LICENCE_ISSUER ""
#endif

#define ELPIS_LICENCE_MAGIC     "elpis1"
/* Domain separation: a signature over a licence cannot be lifted from, or
 * replayed into, any other thing this project ever signs. */
#define ELPIS_LICENCE_CONTEXT   "elpis-licence-v1"
#define ELPIS_LICENCE_MAX_ORG   64
#define ELPIS_LICENCE_MAX_TOKEN 320

typedef enum {
    ELPIS_ED_UNKNOWN    = 0,
    ELPIS_ED_COMMERCIAL = 1,
    ELPIS_ED_COMMUNITY  = 2,
    ELPIS_ED_HOMELAB    = 3,
    ELPIS_ED_EVALUATION = 4
} elpis_edition_t;

typedef struct {
    uint8_t         present;      /* a licence was configured at all       */
    uint8_t         valid;        /* and its signature verified            */
    uint8_t         expired;      /* reported, never enforced -- see below */
    elpis_edition_t edition;
    uint32_t        serial;
    /*
     * Unix seconds, 64-bit on the wire as well as here.  32 bits would have
     * been enough until 2106 and no further, which sounds distant until you
     * issue a hundred-year licence: 36500 days past today overflows it and
     * comes back out as 1990.  A date field that can silently travel
     * backwards is worse than a wide one.
     */
    int64_t         issued;
    int64_t         expires;      /* 0 means perpetual */
    char            org[ELPIS_LICENCE_MAX_ORG + 1];
    char            why[96];      /* why it did not verify, for the log    */
} elpis_licence_t;

const char *elpis_edition_name(elpis_edition_t e);
int         elpis_edition_from_name(const char *s, elpis_edition_t *out);

/* True when this build carries an issuer key and can check a licence. */
int elpis_licence_enabled(void);

/*
 * Decode and verify a token.  Fills `out` either way: on failure `valid` is 0
 * and `why` says what was wrong.  Expiry sets `expired` but never makes the
 * licence invalid -- a resolver that stops resolving because a date passed is
 * a worse outcome than anything this is protecting against.
 */
int elpis_licence_parse(const char *token, int64_t now, elpis_licence_t *out);

/* The signed bytes, shared by the verifier and the issuing tool so there is
 * one definition of what a licence is. */
size_t elpis_licence_payload(const elpis_licence_t *l, uint8_t *out, size_t cap);

/* "2027-01-01", or "never" when t is 0. */
void elpis_licence_date(int64_t t, char *out, size_t outsz);

/* ---- mesh certificates -------------------------------------------- */
/*
 * The issuer's statement that one instance's mesh key belongs to an
 * organisation, until a date.  With mesh-require-licence: yes an instance
 * proves in the handshake that it holds the private half of the key its
 * certificate names, so a certificate copied out of someone's config is no
 * use to anyone else, and one issued to another organisation does not get
 * in.  A separate token from the deployment licence, signed under its own
 * context string, so neither can ever be passed off as the other.
 *
 *   elpism1.<base64url payload>.<base64url signature>
 *
 *   0   1  format version (1)
 *   1   4  serial          big-endian
 *   5   8  issued          unix seconds, signed
 *   13  8  expires         unix seconds, 0 = never
 *   21  32 the instance's X25519 mesh public key
 *   53  1  length of org
 *   54  N  org, UTF-8
 *
 * Unlike a licence, an expired certificate is refused: the mesh only ever
 * makes resolution faster, so retiring a key costs speed and never answers.
 */
#define ELPIS_MESHCERT_MAGIC   "elpism1"
#define ELPIS_MESHCERT_CONTEXT "elpis-mesh-cert-v1"

typedef struct {
    uint8_t  present;
    uint8_t  valid;               /* the signature verified                */
    uint8_t  expired;
    uint32_t serial;
    int64_t  issued;
    int64_t  expires;             /* 0 means never */
    uint8_t  key[32];
    char     org[ELPIS_LICENCE_MAX_ORG + 1];
    char     why[96];
} elpis_meshcert_t;

size_t elpis_meshcert_payload(const elpis_meshcert_t *c, uint8_t *out,
                              size_t cap);
/* As elpis_licence_parse(): `valid` only once the signature checks out
 * against this build's issuer key, `why` otherwise. */
int    elpis_meshcert_parse(const char *token, int64_t now,
                            elpis_meshcert_t *out);

size_t elpis_b64url_encode(const uint8_t *in, size_t n, char *out, size_t cap);
int    elpis_b64url_decode(const char *in, size_t n, uint8_t *out, size_t cap,
                           size_t *outn);
int    elpis_hex_decode(const char *in, uint8_t *out, size_t cap, size_t *outn);

#endif /* ELPIS_LICENCE_H */
