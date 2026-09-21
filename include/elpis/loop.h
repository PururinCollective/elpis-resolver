/*
 * elpis/loop.h -- event loop with epoll, kqueue or poll behind one interface.
 *
 * One loop per worker thread.  A worker owns its listening sockets (via
 * SO_REUSEPORT), its outbound sockets and its in-flight queries, so nothing
 * inside a loop needs locking; only the caches are shared.
 */
#ifndef ELPIS_LOOP_H
#define ELPIS_LOOP_H

#include "elpis/common.h"

#define ELPIS_EV_READ  0x01u
#define ELPIS_EV_WRITE 0x02u
#define ELPIS_EV_ERROR 0x04u
#define ELPIS_EV_HUP   0x08u

typedef struct elpis_loop  elpis_loop_t;
typedef struct elpis_ev    elpis_ev_t;
typedef struct elpis_timer elpis_timer_t;

typedef void (*elpis_ev_cb)(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events);
typedef void (*elpis_timer_cb)(elpis_loop_t *lp, elpis_timer_t *t);

struct elpis_ev {
    int          fd;
    unsigned     mask;
    unsigned     active;
    elpis_ev_cb  cb;
    void        *data;
};

struct elpis_timer {
    uint64_t        deadline_ms;
    unsigned        heap_idx;
    unsigned        active;
    elpis_timer_cb  cb;
    void           *data;
};

elpis_loop_t *elpis_loop_new(unsigned fd_hint);
void          elpis_loop_free(elpis_loop_t *lp);

int  elpis_loop_add(elpis_loop_t *lp, elpis_ev_t *ev, int fd, unsigned mask,
                    elpis_ev_cb cb, void *data);
int  elpis_loop_mod(elpis_loop_t *lp, elpis_ev_t *ev, unsigned mask);
int  elpis_loop_del(elpis_loop_t *lp, elpis_ev_t *ev);

/* Run one iteration; `max_wait_ms` bounds the sleep.  Returns events handled. */
int  elpis_loop_once(elpis_loop_t *lp, int max_wait_ms);
void elpis_loop_stop(elpis_loop_t *lp);
int  elpis_loop_stopped(const elpis_loop_t *lp);

/*
 * How the loop has been spending its time: total turns, turns that did no
 * work, turns that did not wait, and how many timers are pending.  A loop
 * doing real work and a loop spinning look identical in `top`; these tell
 * them apart.
 */
void elpis_loop_spin_stats(elpis_loop_t *lp, uint64_t *iters,
                           uint64_t *idle, uint64_t *nosleep, unsigned *timers,
                           uint32_t *max_turn_ms);

void elpis_timer_add(elpis_loop_t *lp, elpis_timer_t *t, uint64_t delay_ms,
                     elpis_timer_cb cb, void *data);
void elpis_timer_del(elpis_loop_t *lp, elpis_timer_t *t);
ELPIS_INLINE int elpis_timer_active(const elpis_timer_t *t) { return (int)t->active; }

const char *elpis_loop_backend(void);

#endif /* ELPIS_LOOP_H */
