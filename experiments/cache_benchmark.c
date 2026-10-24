/*
 * h2ROV Configuration C: selective invalidation of validation-result cache.
 * Standalone SINGLE-THREADED comparative MICROBENCHMARK.
 * Source: experiments/cache_benchmark.c
 *
 * Build from repository root:
 * gcc -std=gnu11 -O2 -I. \
 *   experiments/cache_benchmark.c -L. -lhrov \
 *   -lrtr -lxxhash -lm -lpthread -o experiments/cache_benchmark
 *
 * Run: LD_LIBRARY_PATH="$PWD" ./experiments/cache_benchmark A|B|C [requests] [update_every]
 *
 * Important: All authorization changes must pass through the wrappers.
 * Unknown record formats, invalid update metadata, or failed underlying
 * updates conservatively clear the entire cache. Real RTR reset/resync and
 * concurrency require additional handling before integration into a router.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "src/hrov_header.h"

#define BUCKETS 257u
#define CAPACITY 8u

typedef struct {
    uint32_t asn;
    uint8_t masklen;
    struct lrtr_ip_addr prefix;
} CacheKey;

typedef struct CacheEntry {
    CacheKey key;
    enum pfxv_state value;
    struct CacheEntry *bucket_next;
    struct CacheEntry *older, *newer;
} CacheEntry;

typedef struct {
    CacheEntry *bucket[BUCKETS];
    CacheEntry *lru, *mru;
    size_t count, capacity;
    unsigned long hits, misses, evictions;
    unsigned long selectively_invalidated, globally_invalidated;
} Cache;

typedef struct {
    struct rov_algo_t original;
    Cache cache;
} CachedValidator;

static uint32_t top_bits(uint8_t n)
{
    return n == 0 ? 0u : (n >= 32 ? UINT32_MAX : UINT32_MAX << (32u - n));
}

/* Canonicalize network prefix in the key; do not cache malformed inputs. */
static CacheKey make_key(uint32_t asn, const struct lrtr_ip_addr *prefix,
                         uint8_t len)
{
    CacheKey k = {0};
    k.asn = asn;
    k.masklen = len;
    k.prefix.ver = prefix->ver;
    if (prefix->ver == LRTR_IPV4) {
        k.prefix.u.addr4.addr = prefix->u.addr4.addr & top_bits(len);
    } else if (prefix->ver == LRTR_IPV6) {
        unsigned remain = len;
        for (unsigned i = 0; i < 4; ++i) {
            unsigned bits = remain > 32u ? 32u : remain;
            k.prefix.u.addr6.addr[i] = prefix->u.addr6.addr[i] & top_bits(bits);
            remain -= bits;
        }
    }
    return k;
}

static uint32_t hash_bytes(uint32_t h, const void *buf, size_t n)
{
    const unsigned char *p = buf;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= UINT32_C(16777619);
    }
    return h;
}

static size_t bucket_for(const CacheKey *k)
{
    uint32_t h = UINT32_C(2166136261);
    h = hash_bytes(h, &k->asn, sizeof(k->asn));
    h = hash_bytes(h, &k->masklen, sizeof(k->masklen));
    h = hash_bytes(h, &k->prefix.ver, sizeof(k->prefix.ver));
    if (k->prefix.ver == LRTR_IPV4)
        h = hash_bytes(h, &k->prefix.u.addr4.addr, sizeof(uint32_t));
    else
        h = hash_bytes(h, k->prefix.u.addr6.addr, 4 * sizeof(uint32_t));
    return h % BUCKETS;
}

static int same_key(const CacheKey *a, const CacheKey *b)
{
    if (a->asn != b->asn || a->masklen != b->masklen ||
        a->prefix.ver != b->prefix.ver) return 0;
    if (a->prefix.ver == LRTR_IPV4)
        return a->prefix.u.addr4.addr == b->prefix.u.addr4.addr;
    return memcmp(a->prefix.u.addr6.addr, b->prefix.u.addr6.addr,
                  4 * sizeof(uint32_t)) == 0;
}

static void unlink_lru(Cache *c, CacheEntry *e)
{
    if (e->older) e->older->newer = e->newer;
    else c->lru = e->newer;
    if (e->newer) e->newer->older = e->older;
    else c->mru = e->older;
    e->older = e->newer = NULL;
}

static void append_mru(Cache *c, CacheEntry *e)
{
    e->older = c->mru;
    e->newer = NULL;
    if (c->mru) c->mru->newer = e;
    else c->lru = e;
    c->mru = e;
}

static void discard(Cache *c, CacheEntry *e)
{
    size_t b = bucket_for(&e->key);
    CacheEntry **pp = &c->bucket[b];
    while (*pp && *pp != e) pp = &(*pp)->bucket_next;
    if (*pp) *pp = e->bucket_next;
    unlink_lru(c, e);
    free(e);
    --c->count;
}

static size_t clear_all(Cache *c)
{
    size_t removed = c->count;
    while (c->lru) discard(c, c->lru);
    c->globally_invalidated += removed;
    return removed;
}

/* ROV dependence: changing authorization P may affect every route R
 * where R is equal to or more-specific than P (any origin ASN, any state).
 * This is an O(number_of_cached_entries) scan in the prototype.
 */
static int route_within_updated_prefix(const CacheKey *route,
                                       const struct lrtr_ip_addr *updated,
                                       uint8_t updated_len)
{
    if (route->prefix.ver != updated->ver || route->masklen < updated_len)
        return 0;
    if (updated->ver == LRTR_IPV4) {
        uint32_t mask = top_bits(updated_len);
        return (route->prefix.u.addr4.addr & mask) ==
               (updated->u.addr4.addr & mask);
    }
    if (updated->ver == LRTR_IPV6) {
        unsigned remain = updated_len;
        for (unsigned i = 0; i < 4; ++i) {
            unsigned bits = remain > 32u ? 32u : remain;
            uint32_t mask = top_bits(bits);
            if ((route->prefix.u.addr6.addr[i] & mask) !=
                (updated->u.addr6.addr[i] & mask)) return 0;
            remain -= bits;
        }
        return 1;
    }
    return 0;
}

static size_t selectively_clear(Cache *c, const struct lrtr_ip_addr *updated,
                                uint8_t updated_len)
{
    size_t removed = 0;
    CacheEntry *e = c->lru;
    while (e) {
        CacheEntry *next = e->newer;
        if (route_within_updated_prefix(&e->key, updated, updated_len)) {
            discard(c, e);
            ++removed;
        }
        e = next;
    }
    c->selectively_invalidated += removed;
    return removed;
}

static int lookup(Cache *c, const CacheKey *key, enum pfxv_state *out)
{
    for (CacheEntry *e = c->bucket[bucket_for(key)]; e; e = e->bucket_next) {
        if (same_key(&e->key, key)) {
            *out = e->value;
            unlink_lru(c, e);
            append_mru(c, e);
            ++c->hits;
            return 1;
        }
    }
    ++c->misses;
    return 0;
}

static void insert(Cache *c, const CacheKey *key, enum pfxv_state value)
{
    if (!c->capacity) return;
    /* Only called for cache misses in this single-threaded prototype. */
    CacheEntry *e = calloc(1, sizeof(*e));
    if (!e) return; /* Allocation failure must not change validation result. */
    if (c->count == c->capacity) {
        discard(c, c->lru);
        ++c->evictions;
    }
    e->key = *key;
    e->value = value;
    size_t b = bucket_for(key);
    e->bucket_next = c->bucket[b];
    c->bucket[b] = e;
    append_mru(c, e);
    ++c->count;
}

static int cached_validate(CachedValidator *v, uint32_t asn,
                           const struct lrtr_ip_addr *prefix, uint8_t masklen,
                           enum pfxv_state *state)
{
    if (!prefix || !state) return ERROR;
    /* Avoid caching malformed data, including unknown address families. */
    if ((prefix->ver == LRTR_IPV4 && masklen > 32) ||
        (prefix->ver == LRTR_IPV6 && masklen > 128) ||
        (prefix->ver != LRTR_IPV4 && prefix->ver != LRTR_IPV6))
        return v->original.rov_pfx_validate(v->original.ht, asn, prefix,
                                            masklen, state);
    CacheKey key = make_key(asn, prefix, masklen);
    if (lookup(&v->cache, &key, state)) return SUCCESS;
    int rc = v->original.rov_pfx_validate(v->original.ht, asn, prefix,
                                           masklen, state);
    if (rc == SUCCESS) insert(&v->cache, &key, *state);
    return rc;
}

/* Extract the covering prefix only for understood TROA PDU types.
 * For HROV/HPDU bitmap updates, safe extraction of affected prefixes
 * needs separate design: use global invalidation for those formats.
 */
static int updated_prefix_from_record(const void *record,
                                      struct lrtr_ip_addr *prefix,
                                      uint8_t *len)
{
    if (!record) return 0;
    const uint8_t type = ((const uint8_t *)record)[1];
    memset(prefix, 0, sizeof(*prefix));
    if (type == TROA_IPV4) {
        const struct pdu_ipv4 *pdu = record;
        if (pdu->prefix_len > 32 || pdu->max_prefix_len > 32 ||
            pdu->max_prefix_len < pdu->prefix_len) return 0;
        prefix->ver = LRTR_IPV4;
        prefix->u.addr4.addr = pdu->prefix;
        *len = pdu->prefix_len;
        return 1;
    }
    if (type == TROA_IPV6) {
        const struct pdu_ipv6 *pdu = record;
        if (pdu->prefix_len > 128 || pdu->max_prefix_len > 128 ||
            pdu->max_prefix_len < pdu->prefix_len) return 0;
        prefix->ver = LRTR_IPV6;
        memcpy(prefix->u.addr6.addr, pdu->prefix, sizeof(pdu->prefix));
        *len = pdu->prefix_len;
        return 1;
    }
    return 0;
}

static int cached_update(CachedValidator *v, void *record, int is_add)
{
    if (!record) return ERROR;
    struct lrtr_ip_addr updated;
    uint8_t len = 0;
    int can_select = updated_prefix_from_record(record, &updated, &len);
    int rc = is_add ? v->original.rov_pfx_add(v->original.ht, record)
                    : v->original.rov_pfx_rm(v->original.ht, record);
    if (rc == SUCCESS && can_select) {
        size_t n = selectively_clear(&v->cache, &updated, len);
        printf("Selective invalidation: removed=%zu retained=%zu\n", n,
               v->cache.count);
    } else {
        /* Conservative fallback covers failed/partial updates and unknown
           record layouts. */
        size_t n = clear_all(&v->cache);
        printf("Global fallback: removed=%zu\n", n);
    }
    return rc;
}


#include <time.h>
#include <inttypes.h>

/* A: original h2ROV; B: global-invalidating LRU; C: selective LRU.
 * Same deterministic workload and authorizations in all three modes.
 * Times exclude initialization and input generation; include validation,
 * cache operations, and authorization add/remove update processing.
 * A single process runs one mode to avoid upstream h2ROV cleanup issues.
 */
#define NUM_ROUTES 128u
#define DEFAULT_REQUESTS 100000u
#define DEFAULT_UPDATE_EVERY 5000u

typedef struct {
    struct lrtr_ip_addr addr;
    uint8_t len;
    uint32_t asn;
} Route;

static double monotonic_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint32_t next_random(uint32_t *s)
{
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return *s = x;
}

static void populate_routes(Route routes[NUM_ROUTES])
{
    for (unsigned i = 0; i < NUM_ROUTES; ++i) {
        char ip[32];
        /* 32 affected prefixes, 96 unaffected ones. */
        if (i < 32)
            snprintf(ip, sizeof(ip), "192.0.%u.0", i);
        else
            snprintf(ip, sizeof(ip), "198.18.%u.0", i - 32);
        memset(&routes[i], 0, sizeof(routes[i]));
        lrtr_ip_str_to_addr(ip, &routes[i].addr);
        routes[i].len = 24;
        routes[i].asn = (i < 32 ? ((i & 1) ? 65003u : 65001u) : 65004u);
    }
}

static int do_update(CachedValidator *v, const struct pdu_ipv4 *record,
                     char mode, int is_add)
{
    int rc = is_add ? v->original.rov_pfx_add(v->original.ht, (void *)record)
                    : v->original.rov_pfx_rm(v->original.ht, (void *)record);
    if (mode == 'B') {
        clear_all(&v->cache);
    } else if (mode == 'C') {
        if (rc == SUCCESS) {
            struct lrtr_ip_addr changed;
            uint8_t len = 0;
            if (updated_prefix_from_record(record, &changed, &len))
                selectively_clear(&v->cache, &changed, len);
            else
                clear_all(&v->cache);
        } else {
            clear_all(&v->cache);
        }
    }
    return rc;
}

static uint64_t digest_step(uint64_t h, enum pfxv_state s, size_t i)
{
    /* A deterministic digest of the entire output sequence. */
    h ^= (uint64_t)(unsigned)s + UINT64_C(17) * (uint64_t)i;
    return h * UINT64_C(1099511628211);
}

int main(int argc, char **argv)
{
    if (argc < 2 || argv[1][0] < 'A' || argv[1][0] > 'C' || argv[1][1]) {
        fprintf(stderr, "Usage: %s A|B|C [requests >= 1] [update_every >= 1] [capacity >= 1] [seed >= 1]\n", argv[0]);
        return 2;
    }
    char mode = argv[1][0];
    size_t requests = argc > 2 ? (size_t)strtoull(argv[2], NULL, 10) : DEFAULT_REQUESTS;
    size_t update_every = argc > 3 ? (size_t)strtoull(argv[3], NULL, 10) : DEFAULT_UPDATE_EVERY;
    size_t capacity = argc > 4 ? (size_t)strtoull(argv[4], NULL, 10) : NUM_ROUTES;
    uint32_t seed = argc > 5 ? (uint32_t)strtoul(argv[5], NULL, 10) : 12345u;
    if (!requests || !update_every || !capacity || !seed || requests > 20000000u || capacity > 100000u) {
        fputs("Invalid benchmark parameters\n", stderr);
        return 2;
    }

    Route routes[NUM_ROUTES];
    populate_routes(routes);
    /* Workload is generated once outside the timed section. */
    uint8_t *indices = malloc(requests);
    if (!indices) {
        perror("malloc");
        return 1;
    }
    uint32_t rand_state = seed;
    for (size_t i = 0; i < requests; ++i)
        indices[i] = (uint8_t)(next_random(&rand_state) % NUM_ROUTES);

    CachedValidator v = {0};
    v.original = hrov_nlbs_binary;
    v.original.wide_threshold = 5;
    v.cache.capacity = capacity;
    v.original.rov_init(&v.original);
    if (!v.original.ht) {
        fputs("Validator initialization failed\n", stderr);
        free(indices);
        return 1;
    }

    struct pdu_ipv4 roa = {0};
    char prefix[] = "192.0.0.0";
    init_pdu_v4(&roa, TROA_IPV4, prefix, 16, 24, 65001);
    if (do_update(&v, &roa, mode, 1) != SUCCESS) {
        fputs("Initial authorization insertion failed\n", stderr);
        free(indices);
        return 1;
    }

    int present = 1;
    uint64_t digest = UINT64_C(1469598103934665603);
    double t0 = monotonic_seconds();
    for (size_t i = 0; i < requests; ++i) {
        if (i > 0 && i % update_every == 0) {
            int add = !present;
            if (do_update(&v, &roa, mode, add) != SUCCESS) {
                fprintf(stderr, "Authorization update failed at request %zu\n", i);
                free(indices);
                return 1;
            }
            present = add;
        }
        const Route *r = &routes[indices[i]];
        enum pfxv_state state = BGP_PFXV_STATE_NOT_FOUND;
        int rc;
        if (mode == 'A') {
            rc = v.original.rov_pfx_validate(v.original.ht, r->asn,
                                             &r->addr, r->len, &state);
        } else {
            rc = cached_validate(&v, r->asn, &r->addr, r->len, &state);
        }
        if (rc != SUCCESS) {
            fprintf(stderr, "Validation failed at request %zu (rc=%d)\n", i, rc);
            free(indices);
            return 1;
        }
        /* Check expected semantics independently for our synthetic dataset. */
        enum pfxv_state expected = BGP_PFXV_STATE_NOT_FOUND;
        if (indices[i] < 32 && present)
            expected = (r->asn == 65001 ? BGP_PFXV_STATE_VALID : BGP_PFXV_STATE_INVALID);
        if (state != expected) {
            fprintf(stderr, "CLASSIFICATION ERROR: mode %c request %zu route %u actual %d expected %d\n",
                    mode, i, (unsigned)indices[i], state, expected);
            free(indices);
            return 1;
        }
        digest = digest_step(digest, state, i);
    }
    double elapsed = monotonic_seconds() - t0;
    printf("mode,requests,update_every,capacity,seed,seconds,validations_per_second,hits,misses,evictions,selectively_invalidated,globally_invalidated,digest\n");
    printf("%c,%zu,%zu,%zu,%" PRIu32 ",%.9f,%.3f,%lu,%lu,%lu,%lu,%lu,%" PRIu64 "\n",
           mode, requests, update_every, capacity, seed, elapsed,
           (double)requests / elapsed,
           v.cache.hits, v.cache.misses, v.cache.evictions,
           v.cache.selectively_invalidated, v.cache.globally_invalidated,
           digest);
    free(indices);
    clear_all(&v.cache);
    /* No h2ROV release: upstream implementation's cleanup is incomplete. */
    return 0;
}
