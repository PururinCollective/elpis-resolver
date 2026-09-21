/*
 * loop.c -- event loop.
 */
#include "elpis/loop.h"
#include "elpis/util.h"
#include "elpis/log.h"

#include <errno.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/epoll.h>
#  define USE_EPOLL 1
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
      defined(__OpenBSD__) || defined(__DragonFly__)
#  include <sys/event.h>
#  include <sys/time.h>
#  define USE_KQUEUE 1
#else
#  include <poll.h>
#  define USE_POLL 1
#endif

#define TIMER_HEAP_MIN 64

struct elpis_loop {
    int              backend_fd;
    int              stop;
    elpis_ev_t     **evs;          /* indexed by fd */
    unsigned         nevs;
#if defined(USE_POLL)
    struct pollfd   *pfd;
    elpis_ev_t     **pev;
    unsigned         npfd, cpfd;
#endif
    elpis_timer_t  **heap;
    unsigned         nheap, cheap;
};

/* ------------------------------------------------------------------ */
/* fd -> event map                                                     */
/* ------------------------------------------------------------------ */

static int evmap_ensure(elpis_loop_t *lp, int fd)
{
    unsigned want;
    elpis_ev_t **p;

    if (fd < 0)
        return ELPIS_ERR;
    if ((unsigned)fd < lp->nevs)
        return ELPIS_OK;

    want = lp->nevs ? lp->nevs : 64u;
    while (want <= (unsigned)fd)
        want *= 2u;
    p = (elpis_ev_t **)elpis_realloc(lp->evs, want * sizeof *p);
    if (p == NULL)
        return ELPIS_ENOMEM;
    memset(p + lp->nevs, 0, (want - lp->nevs) * sizeof *p);
    lp->evs = p;
    lp->nevs = want;
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Timer heap                                                          */
/* ------------------------------------------------------------------ */

static void heap_swap(elpis_loop_t *lp, unsigned a, unsigned b)
{
    elpis_timer_t *t = lp->heap[a];
    lp->heap[a] = lp->heap[b];
    lp->heap[b] = t;
    lp->heap[a]->heap_idx = a;
    lp->heap[b]->heap_idx = b;
}

static void heap_up(elpis_loop_t *lp, unsigned i)
{
    while (i > 0) {
        unsigned p = (i - 1u) / 2u;
        if (lp->heap[p]->deadline_ms <= lp->heap[i]->deadline_ms)
            break;
        heap_swap(lp, i, p);
        i = p;
    }
}

static void heap_down(elpis_loop_t *lp, unsigned i)
{
    for (;;) {
        unsigned l = i * 2u + 1u, r = l + 1u, m = i;
        if (l < lp->nheap && lp->heap[l]->deadline_ms < lp->heap[m]->deadline_ms)
            m = l;
        if (r < lp->nheap && lp->heap[r]->deadline_ms < lp->heap[m]->deadline_ms)
            m = r;
        if (m == i)
            break;
        heap_swap(lp, i, m);
        i = m;
    }
}

void elpis_timer_add(elpis_loop_t *lp, elpis_timer_t *t, uint64_t delay_ms,
                     elpis_timer_cb cb, void *data)
{
    if (t->active)
        elpis_timer_del(lp, t);

    if (lp->nheap == lp->cheap) {
        unsigned want = lp->cheap ? lp->cheap * 2u : TIMER_HEAP_MIN;
        elpis_timer_t **h = (elpis_timer_t **)elpis_realloc(lp->heap,
                                                            want * sizeof *h);
        if (h == NULL)
            return;
        lp->heap = h;
        lp->cheap = want;
    }
    t->deadline_ms = elpis_cached_now_ms() + delay_ms;
    t->cb = cb;
    t->data = data;
    t->active = 1;
    t->heap_idx = lp->nheap;
    lp->heap[lp->nheap++] = t;
    heap_up(lp, t->heap_idx);
}

void elpis_timer_del(elpis_loop_t *lp, elpis_timer_t *t)
{
    unsigned i;
    if (!t->active)
        return;
    i = t->heap_idx;
    t->active = 0;
    if (i >= lp->nheap || lp->heap[i] != t)
        return;
    lp->nheap--;
    if (i != lp->nheap) {
        lp->heap[i] = lp->heap[lp->nheap];
        lp->heap[i]->heap_idx = i;
        heap_up(lp, i);
        heap_down(lp, i);
    }
}

static int timers_run(elpis_loop_t *lp)
{
    uint64_t now = elpis_cached_now_ms();
    int n = 0;

    while (lp->nheap > 0 && lp->heap[0]->deadline_ms <= now) {
        elpis_timer_t *t = lp->heap[0];
        elpis_timer_del(lp, t);
        if (t->cb)
            t->cb(lp, t);
        n++;
        if (n > 4096)
            break;          /* let I/O in even under a timer storm */
    }
    return n;
}

static int timers_next_ms(elpis_loop_t *lp, int cap)
{
    uint64_t now;
    int64_t d;

    if (lp->nheap == 0)
        return cap;
    now = elpis_cached_now_ms();
    d = (int64_t)lp->heap[0]->deadline_ms - (int64_t)now;
    if (d < 0)
        d = 0;
    if (cap >= 0 && d > cap)
        return cap;
    return (int)d;
}

/* ------------------------------------------------------------------ */
/* Backend                                                             */
/* ------------------------------------------------------------------ */

elpis_loop_t *elpis_loop_new(unsigned fd_hint)
{
    elpis_loop_t *lp = (elpis_loop_t *)elpis_calloc(1, sizeof *lp);
    if (lp == NULL)
        return NULL;

#if defined(USE_EPOLL)
    lp->backend_fd = epoll_create1(EPOLL_CLOEXEC);
    if (lp->backend_fd < 0) {
        elpis_error("epoll_create1: %s", strerror(errno));
        elpis_free(lp);
        return NULL;
    }
#elif defined(USE_KQUEUE)
    lp->backend_fd = kqueue();
    if (lp->backend_fd < 0) {
        elpis_error("kqueue: %s", strerror(errno));
        elpis_free(lp);
        return NULL;
    }
#else
    lp->backend_fd = -1;
#endif

    if (evmap_ensure(lp, (int)(fd_hint ? fd_hint : 64u)) != ELPIS_OK) {
        elpis_loop_free(lp);
        return NULL;
    }
    return lp;
}

void elpis_loop_free(elpis_loop_t *lp)
{
    if (lp == NULL)
        return;
    if (lp->backend_fd >= 0)
        close(lp->backend_fd);
    elpis_free(lp->evs);
    elpis_free(lp->heap);
#if defined(USE_POLL)
    elpis_free(lp->pfd);
    elpis_free(lp->pev);
#endif
    elpis_free(lp);
}

#if defined(USE_EPOLL)
static uint32_t to_epoll(unsigned mask)
{
    uint32_t e = 0;
    if (mask & ELPIS_EV_READ)  e |= EPOLLIN;
    if (mask & ELPIS_EV_WRITE) e |= EPOLLOUT;
    return e;
}
#endif

int elpis_loop_add(elpis_loop_t *lp, elpis_ev_t *ev, int fd, unsigned mask,
                   elpis_ev_cb cb, void *data)
{
    if (evmap_ensure(lp, fd) != ELPIS_OK)
        return ELPIS_ENOMEM;

    ev->fd     = fd;
    ev->mask   = mask;
    ev->cb     = cb;
    ev->data   = data;
    ev->active = 1;
    lp->evs[fd] = ev;

#if defined(USE_EPOLL)
    {
        struct epoll_event e;
        memset(&e, 0, sizeof e);
        e.events = to_epoll(mask);
        e.data.fd = fd;
        if (epoll_ctl(lp->backend_fd, EPOLL_CTL_ADD, fd, &e) != 0) {
            elpis_error("epoll_ctl(add, %d): %s", fd, strerror(errno));
            lp->evs[fd] = NULL;
            ev->active = 0;
            return ELPIS_ERR;
        }
    }
#elif defined(USE_KQUEUE)
    {
        struct kevent ke[2];
        int n = 0;
        EV_SET(&ke[n++], fd, EVFILT_READ,  (mask & ELPIS_EV_READ)  ? EV_ADD : EV_DISABLE, 0, 0, ev);
        EV_SET(&ke[n++], fd, EVFILT_WRITE, (mask & ELPIS_EV_WRITE) ? EV_ADD : EV_DISABLE, 0, 0, ev);
        if (kevent(lp->backend_fd, ke, n, NULL, 0, NULL) < 0 && errno != ENOENT) {
            elpis_error("kevent(add, %d): %s", fd, strerror(errno));
            lp->evs[fd] = NULL;
            ev->active = 0;
            return ELPIS_ERR;
        }
    }
#endif
    return ELPIS_OK;
}

int elpis_loop_mod(elpis_loop_t *lp, elpis_ev_t *ev, unsigned mask)
{
    if (!ev->active)
        return ELPIS_ERR;
    if (ev->mask == mask)
        return ELPIS_OK;
    ev->mask = mask;

#if defined(USE_EPOLL)
    {
        struct epoll_event e;
        memset(&e, 0, sizeof e);
        e.events = to_epoll(mask);
        e.data.fd = ev->fd;
        if (epoll_ctl(lp->backend_fd, EPOLL_CTL_MOD, ev->fd, &e) != 0)
            return ELPIS_ERR;
    }
#elif defined(USE_KQUEUE)
    {
        struct kevent ke[2];
        int n = 0;
        EV_SET(&ke[n++], ev->fd, EVFILT_READ,
               (mask & ELPIS_EV_READ) ? (EV_ADD | EV_ENABLE) : EV_DISABLE, 0, 0, ev);
        EV_SET(&ke[n++], ev->fd, EVFILT_WRITE,
               (mask & ELPIS_EV_WRITE) ? (EV_ADD | EV_ENABLE) : EV_DISABLE, 0, 0, ev);
        if (kevent(lp->backend_fd, ke, n, NULL, 0, NULL) < 0)
            return ELPIS_ERR;
    }
#endif
    return ELPIS_OK;
}

int elpis_loop_del(elpis_loop_t *lp, elpis_ev_t *ev)
{
    if (!ev->active)
        return ELPIS_OK;
    ev->active = 0;
    if (ev->fd >= 0 && (unsigned)ev->fd < lp->nevs)
        lp->evs[ev->fd] = NULL;

#if defined(USE_EPOLL)
    (void)epoll_ctl(lp->backend_fd, EPOLL_CTL_DEL, ev->fd, NULL);
#elif defined(USE_KQUEUE)
    {
        struct kevent ke[2];
        EV_SET(&ke[0], ev->fd, EVFILT_READ,  EV_DELETE, 0, 0, NULL);
        EV_SET(&ke[1], ev->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        (void)kevent(lp->backend_fd, ke, 2, NULL, 0, NULL);
    }
#endif
    return ELPIS_OK;
}

#define MAX_EVENTS 256

int elpis_loop_once(elpis_loop_t *lp, int max_wait_ms)
{
    int wait_ms, handled = 0;

    elpis_clock_tick();
    handled += timers_run(lp);
    wait_ms = timers_next_ms(lp, max_wait_ms);
    if (handled > 0 && wait_ms > 0)
        wait_ms = 0;          /* a timer may have queued work; do not sleep */

#if defined(USE_EPOLL)
    {
        struct epoll_event evs[MAX_EVENTS];
        int n = epoll_wait(lp->backend_fd, evs, MAX_EVENTS, wait_ms);
        int i;
        if (n < 0) {
            if (errno != EINTR)
                elpis_error("epoll_wait: %s", strerror(errno));
            return handled;
        }
        elpis_clock_tick();
        for (i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            elpis_ev_t *ev;
            unsigned mask = 0;
            if (fd < 0 || (unsigned)fd >= lp->nevs)
                continue;
            ev = lp->evs[fd];
            if (ev == NULL || !ev->active)
                continue;
            if (evs[i].events & EPOLLIN)  mask |= ELPIS_EV_READ;
            if (evs[i].events & EPOLLOUT) mask |= ELPIS_EV_WRITE;
            if (evs[i].events & EPOLLERR) mask |= ELPIS_EV_ERROR;
            if (evs[i].events & EPOLLHUP) mask |= ELPIS_EV_HUP;
            ev->cb(lp, ev, mask);
            handled++;
        }
    }
#elif defined(USE_KQUEUE)
    {
        struct kevent evs[MAX_EVENTS];
        struct timespec ts, *tsp = NULL;
        int n, i;
        if (wait_ms >= 0) {
            ts.tv_sec  = wait_ms / 1000;
            ts.tv_nsec = (long)(wait_ms % 1000) * 1000000L;
            tsp = &ts;
        }
        n = kevent(lp->backend_fd, NULL, 0, evs, MAX_EVENTS, tsp);
        if (n < 0) {
            if (errno != EINTR)
                elpis_error("kevent: %s", strerror(errno));
            return handled;
        }
        elpis_clock_tick();
        for (i = 0; i < n; i++) {
            elpis_ev_t *ev = (elpis_ev_t *)evs[i].udata;
            unsigned mask = 0;
            if (ev == NULL || !ev->active)
                continue;
            if (evs[i].filter == EVFILT_READ)  mask |= ELPIS_EV_READ;
            if (evs[i].filter == EVFILT_WRITE) mask |= ELPIS_EV_WRITE;
            if (evs[i].flags & EV_ERROR)       mask |= ELPIS_EV_ERROR;
            if (evs[i].flags & EV_EOF)         mask |= ELPIS_EV_HUP;
            ev->cb(lp, ev, mask);
            handled++;
        }
    }
#else
    {
        unsigned i, n = 0;
        int r;
        /* Rebuild the pollfd array each pass; the fd set is small per worker. */
        if (lp->cpfd < lp->nevs) {
            struct pollfd *np = (struct pollfd *)elpis_realloc(lp->pfd,
                                    lp->nevs * sizeof *np);
            elpis_ev_t **ne = (elpis_ev_t **)elpis_realloc(lp->pev,
                                    lp->nevs * sizeof *ne);
            if (np == NULL || ne == NULL)
                return handled;
            lp->pfd = np;
            lp->pev = ne;
            lp->cpfd = lp->nevs;
        }
        for (i = 0; i < lp->nevs; i++) {
            elpis_ev_t *ev = lp->evs[i];
            if (ev == NULL || !ev->active)
                continue;
            lp->pfd[n].fd = ev->fd;
            lp->pfd[n].events = (short)(((ev->mask & ELPIS_EV_READ) ? POLLIN : 0) |
                                        ((ev->mask & ELPIS_EV_WRITE) ? POLLOUT : 0));
            lp->pfd[n].revents = 0;
            lp->pev[n] = ev;
            n++;
        }
        r = poll(lp->pfd, n, wait_ms);
        if (r < 0) {
            if (errno != EINTR)
                elpis_error("poll: %s", strerror(errno));
            return handled;
        }
        elpis_clock_tick();
        for (i = 0; i < n && r > 0; i++) {
            elpis_ev_t *ev = lp->pev[i];
            unsigned mask = 0;
            if (lp->pfd[i].revents == 0)
                continue;
            r--;
            if (ev == NULL || !ev->active)
                continue;
            if (lp->pfd[i].revents & POLLIN)  mask |= ELPIS_EV_READ;
            if (lp->pfd[i].revents & POLLOUT) mask |= ELPIS_EV_WRITE;
            if (lp->pfd[i].revents & POLLERR) mask |= ELPIS_EV_ERROR;
            if (lp->pfd[i].revents & POLLHUP) mask |= ELPIS_EV_HUP;
            ev->cb(lp, ev, mask);
            handled++;
        }
    }
#endif

    elpis_clock_tick();
    handled += timers_run(lp);
    return handled;
}

void elpis_loop_stop(elpis_loop_t *lp)   { lp->stop = 1; }
int  elpis_loop_stopped(const elpis_loop_t *lp) { return lp->stop; }

const char *elpis_loop_backend(void)
{
#if defined(USE_EPOLL)
    return "epoll";
#elif defined(USE_KQUEUE)
    return "kqueue";
#else
    return "poll";
#endif
}
