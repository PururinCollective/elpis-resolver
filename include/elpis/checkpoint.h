/*
 * elpis/checkpoint.h -- the questions clients ask, kept across a restart.
 *
 * A restarted resolver starts with empty caches, and the first minutes of
 * queries all pay for the full referral chain.  The checkpoint is a list of
 * the questions clients asked most, written every checkpoint-interval by a
 * thread of its own and never at shutdown, so a restart costs no more time
 * than it did before.  At startup the list is read back and every name on it
 * resolved again, most valuable first, at warm-rate queries a second.
 *
 * Names only, never answers.  Most answers expire within minutes, and one
 * read back from disk would need its DNSSEC status proven all over again; a
 * name read back is simply asked again, and the answer comes from the
 * authorities as it always does.  The file is still a list of what clients
 * looked up, so it is off unless a path is configured, and written 0600.
 */
#ifndef ELPIS_CHECKPOINT_H
#define ELPIS_CHECKPOINT_H

#include "elpis/ctx.h"

/* The first line of every checkpoint.  A file without it is left alone. */
#define ELPIS_CKPT_MAGIC "# elpis checkpoint 1"

typedef struct {
    uint64_t hits;          /* estimated                                 */
    uint64_t score;         /* filled in by elpis_ckpt_rank()            */
    uint32_t name_off;      /* into the list's name arena                */
    uint16_t qtype;
    uint16_t cost_ms;       /* slowest resolution seen                   */
    uint8_t  namelen;
    uint8_t  kflags;        /* ELPIS_MK_DO / ELPIS_MK_CD                 */
} elpis_ckpt_ent_t;

typedef struct {
    elpis_ckpt_ent_t *ent;
    unsigned          n, cap;
    uint8_t          *names;    /* case-folded wire names, back to back */
    size_t            names_len, names_cap;
} elpis_ckpt_list_t;

void elpis_ckpt_list_init(elpis_ckpt_list_t *l);
void elpis_ckpt_list_free(elpis_ckpt_list_t *l);
int  elpis_ckpt_list_add(elpis_ckpt_list_t *l, const uint8_t *qname,
                         uint8_t qnamelen, uint16_t qtype, uint8_t kflags,
                         uint64_t hits, uint32_t cost_ms);
ELPIS_INLINE const uint8_t *elpis_ckpt_name(const elpis_ckpt_list_t *l,
                                            const elpis_ckpt_ent_t *e)
{
    return l->names + e->name_off;
}

/*
 * What warming a name is worth: how often it is asked, times how long it
 * takes cold.  A name whose servers are a millisecond away costs nothing to
 * resolve on demand; one on the far side of the world is where the first
 * client after a restart would wait.
 */
uint64_t elpis_ckpt_score(uint64_t hits, uint32_t cost_ms);
/* Best first, keeping at most `max`. */
void elpis_ckpt_rank(elpis_ckpt_list_t *l, unsigned max);

/*
 * Every class-IN question in the message cache that clients asked an
 * estimated `min_hits` times or more, ranked, at most `max` of them.
 */
int  elpis_ckpt_collect(elpis_cache_t *mcache, uint64_t min_hits, unsigned max,
                        elpis_ckpt_list_t *out);

/* Replace `path` whole or not at all: a temporary file, fsync, rename. */
int  elpis_ckpt_write(const char *path, const elpis_ckpt_list_t *l);
/*
 * Read at most `max` entries, ranked.  ELPIS_ENOTFOUND when there is no file,
 * ELPIS_EFORMAT when there is one but it is not a checkpoint.  Lines that do
 * not parse are skipped and counted in `*bad`.
 */
int  elpis_ckpt_read(const char *path, unsigned max, elpis_ckpt_list_t *l,
                     unsigned *bad);

/*
 * Add `from` into `into`, each count divided by `div` (rounded up): a
 * question already there has the hits added.  Repeats are folded together;
 * the result is not ranked.
 */
int  elpis_ckpt_merge(elpis_ckpt_list_t *into, const elpis_ckpt_list_t *from,
                      unsigned div);

/* ---- process lifecycle (the warm-up itself is in resolver.h) ---- */
/* Read the configured checkpoint for the warm-up, which `nworkers` workers
 * share.  Before the workers start. */
void  elpis_ckpt_load(elpis_ctx_t *ctx, unsigned nworkers);
/* With a mesh, what the checkpoint held at startup, for it to merge with
 * the peers' lists; the list is handed over and left empty here. */
void  elpis_ckpt_take_startup(elpis_ckpt_list_t *out);
/*
 * Queue a list to be warmed, ranked, best first; `what` names it in the log.
 * The job takes the names and leaves `l` empty.  Any thread.
 */
int   elpis_warmup_submit(elpis_ckpt_list_t *l, const char *what);
/* 1 when a writer thread should run. */
int   elpis_ckpt_writing(const elpis_ctx_t *ctx);
/* The writer thread. */
void *elpis_ckpt_main(void *ctx);
/* After every worker has stopped. */
void  elpis_ckpt_fini(void);

#endif /* ELPIS_CHECKPOINT_H */
