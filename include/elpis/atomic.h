/*
 * elpis/atomic.h -- minimal atomics shim.
 *
 * C99 predates <stdatomic.h>, so we use compiler intrinsics where available
 * and fall back to a global mutex otherwise.  Only the few operations the
 * resolver actually needs are exposed.
 */
#ifndef ELPIS_ATOMIC_H
#define ELPIS_ATOMIC_H

#include "elpis/common.h"

#if defined(__GNUC__) && \
    (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7) || defined(__clang__))
#  define ELPIS_HAVE_ATOMICS 1
#  define elpis_atomic_add64(p, v)  __atomic_add_fetch((p), (v), __ATOMIC_RELAXED)
#  define elpis_atomic_sub64(p, v)  __atomic_sub_fetch((p), (v), __ATOMIC_RELAXED)
#  define elpis_atomic_load64(p)    __atomic_load_n((p), __ATOMIC_RELAXED)
#  define elpis_atomic_store64(p,v) __atomic_store_n((p), (v), __ATOMIC_RELAXED)
#  define elpis_atomic_add32(p, v)  __atomic_add_fetch((p), (v), __ATOMIC_RELAXED)
#  define elpis_atomic_load32(p)    __atomic_load_n((p), __ATOMIC_RELAXED)
#  define elpis_atomic_store32(p,v) __atomic_store_n((p), (v), __ATOMIC_RELAXED)
#  define elpis_atomic_cas32(p,e,d) \
       __atomic_compare_exchange_n((p), (e), (d), 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)
#  define elpis_barrier()           __atomic_thread_fence(__ATOMIC_SEQ_CST)
#elif defined(__GNUC__)
#  define ELPIS_HAVE_ATOMICS 1
#  define elpis_atomic_add64(p, v)  __sync_add_and_fetch((p), (v))
#  define elpis_atomic_sub64(p, v)  __sync_sub_and_fetch((p), (v))
#  define elpis_atomic_load64(p)    __sync_fetch_and_add((p), 0)
#  define elpis_atomic_store64(p,v) do { __sync_synchronize(); *(p) = (v); } while (0)
#  define elpis_atomic_add32(p, v)  __sync_add_and_fetch((p), (v))
#  define elpis_atomic_load32(p)    __sync_fetch_and_add((p), 0)
#  define elpis_atomic_store32(p,v) do { __sync_synchronize(); *(p) = (v); } while (0)
#  define elpis_barrier()           __sync_synchronize()
#else
#  define ELPIS_HAVE_ATOMICS 0
   /* Single-threaded fallback: the build refuses >1 worker without atomics. */
#  define elpis_atomic_add64(p, v)  (*(p) += (v))
#  define elpis_atomic_sub64(p, v)  (*(p) -= (v))
#  define elpis_atomic_load64(p)    (*(p))
#  define elpis_atomic_store64(p,v) (*(p) = (v))
#  define elpis_atomic_add32(p, v)  (*(p) += (v))
#  define elpis_atomic_load32(p)    (*(p))
#  define elpis_atomic_store32(p,v) (*(p) = (v))
#  define elpis_barrier()           ((void)0)
#endif

#endif /* ELPIS_ATOMIC_H */
