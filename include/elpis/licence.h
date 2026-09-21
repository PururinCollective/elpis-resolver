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
    uint32_t        issued;       /* unix seconds */
    uint32_t        expires;      /* unix seconds; 0 means perpetual       */
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
int elpis_licence_parse(const char *token, uint32_t now, elpis_licence_t *out);

/* The signed bytes, shared by the verifier and the issuing tool so there is
 * one definition of what a licence is. */
size_t elpis_licence_payload(const elpis_licence_t *l, uint8_t *out, size_t cap);

/* "2027-01-01", or "never" when t is 0. */
void elpis_licence_date(uint32_t t, char *out, size_t outsz);

size_t elpis_b64url_encode(const uint8_t *in, size_t n, char *out, size_t cap);
int    elpis_b64url_decode(const char *in, size_t n, uint8_t *out, size_t cap,
                           size_t *outn);
int    elpis_hex_decode(const char *in, uint8_t *out, size_t cap, size_t *outn);

#endif /* ELPIS_LICENCE_H */
