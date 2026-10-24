/*
 * h2ROV Configuration C: selective invalidation of validation-result cache.
 * Extended, SINGLE-THREADED correctness prototype; no FRR integration.
 * Source: experiments/selective_cache_test.c
 *
 * Build from repository root:
 * gcc -std=gnu11 -O0 -g -Wall -Wextra -I. \
 *   experiments/selective_cache_test.c -L. -lhrov \
 *   -lrtr -lxxhash -lm -lpthread -o experiments/selective_cache_test
 *
 * Run: LD_LIBRARY_PATH="$PWD" timeout 10s ./experiments/selective_cache_test
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

static const char *state_name(enum pfxv_state s)
{
    switch (s) {
    case BGP_PFXV_STATE_VALID: return "VALID";
    case BGP_PFXV_STATE_INVALID: return "INVALID";
    case BGP_PFXV_STATE_NOT_FOUND: return "NOTFOUND";
    default: return "UNKNOWN";
    }
}

static int check(CachedValidator *v, const char *address, uint8_t len,
                 uint32_t asn, enum pfxv_state expected, int expected_hit)
{
    struct lrtr_ip_addr prefix = {0};
    lrtr_ip_str_to_addr(address, &prefix);
    unsigned long old_hits = v->cache.hits;
    unsigned long old_misses = v->cache.misses;
    enum pfxv_state actual = BGP_PFXV_STATE_NOT_FOUND;
    int rc = cached_validate(v, asn, &prefix, len, &actual);
    int hit = v->cache.hits > old_hits;
    int miss = v->cache.misses > old_misses;
    int ok = (rc == SUCCESS && actual == expected &&
              (expected_hit ? hit : miss));
    printf("%-15s/%-3u AS%-6u %-8s expected %-8s cache=%-4s %s\n",
           address, (unsigned)len, asn, state_name(actual),
           state_name(expected), hit ? "HIT" : (miss ? "MISS" : "NONE"),
           ok ? "PASS" : "FAIL");
    return ok;
}

/* Compare every cached lookup with the underlying original validator.
 * Besides checking the classification, verify the expected cache behavior.
 * These tests remain single-threaded and are not performance benchmarks.
 */
static int check_with_oracle(CachedValidator *v, const char *address,
                             uint8_t len, uint32_t asn,
                             enum pfxv_state expected, int expected_hit)
{
    struct lrtr_ip_addr pfx = {0};
    lrtr_ip_str_to_addr(address, &pfx);
    enum pfxv_state baseline = BGP_PFXV_STATE_NOT_FOUND;
    enum pfxv_state cached = BGP_PFXV_STATE_NOT_FOUND;
    int baseline_rc = v->original.rov_pfx_validate(v->original.ht, asn,
                                                     &pfx, len, &baseline);
    unsigned long hits_before = v->cache.hits;
    unsigned long misses_before = v->cache.misses;
    int cached_rc = cached_validate(v, asn, &pfx, len, &cached);
    int was_hit = v->cache.hits == hits_before + 1;
    int was_miss = v->cache.misses == misses_before + 1;
    int ok = baseline_rc == SUCCESS && cached_rc == SUCCESS &&
             baseline == expected && cached == baseline &&
             (expected_hit ? was_hit : was_miss);
    printf("%-15s/%-3u AS%-6u baseline=%-8s cached=%-8s "
           "expected=%-8s cache=%-4s %s\n",
           address, (unsigned)len, asn,
           state_name(baseline), state_name(cached), state_name(expected),
           was_hit ? "HIT" : (was_miss ? "MISS" : "NONE"),
           ok ? "PASS" : "FAIL");
    return ok;
}

int main(void)
{
    CachedValidator v = {0};
    v.original = hrov_nlbs_binary;
    v.original.wide_threshold = 5;
    v.cache.capacity = CAPACITY;
    v.original.rov_init(&v.original);
    if (!v.original.ht) {
        fputs("h2ROV initialization failed\n", stderr);
        return EXIT_FAILURE;
    }

    struct pdu_ipv4 roa = {0};
    char roa_addr[] = "192.0.2.0";
    init_pdu_v4(&roa, TROA_IPV4, roa_addr, 24, 24, 65001);
    if (cached_update(&v, &roa, 1) != SUCCESS) {
        fputs("initial authorization insertion failed\n", stderr);
        return EXIT_FAILURE;
    }

    int passed = 0, total = 0;
#define TEST(addr, len, asn, expected, hit) do { \
        ++total; passed += check(&v, addr, len, asn, expected, hit); \
    } while (0)
    puts("=== Populate cache ===");
    TEST("192.0.2.0", 24, 65001, BGP_PFXV_STATE_VALID, 0);
    TEST("192.0.2.0", 24, 65003, BGP_PFXV_STATE_INVALID, 0);
    TEST("192.0.2.128", 25, 65001, BGP_PFXV_STATE_INVALID, 0);
    TEST("198.51.100.0", 24, 65004, BGP_PFXV_STATE_NOT_FOUND, 0);
    TEST("203.0.113.0", 24, 65005, BGP_PFXV_STATE_NOT_FOUND, 0);
    TEST("192.0.2.0", 24, 65001, BGP_PFXV_STATE_VALID, 1);
    TEST("198.51.100.0", 24, 65004, BGP_PFXV_STATE_NOT_FOUND, 1);
    int before_ok = (v.cache.count == 5 && v.cache.hits == 2 &&
                     v.cache.misses == 5 && v.cache.evictions == 0);
    printf("Before withdrawal: hits=%lu misses=%lu entries=%zu => %s\n",
           v.cache.hits, v.cache.misses, v.cache.count,
           before_ok ? "PASS" : "FAIL");

    puts("=== Withdraw ROA; preserve unrelated cache entries ===");
    int remove_ok = cached_update(&v, &roa, 0) == SUCCESS;
    int selective_ok = (v.cache.count == 2 &&
                        v.cache.selectively_invalidated == 3 &&
                        v.cache.globally_invalidated == 0);
    TEST("198.51.100.0", 24, 65004, BGP_PFXV_STATE_NOT_FOUND, 1);
    TEST("203.0.113.0", 24, 65005, BGP_PFXV_STATE_NOT_FOUND, 1);
    TEST("192.0.2.0", 24, 65001, BGP_PFXV_STATE_NOT_FOUND, 0);
    TEST("192.0.2.0", 24, 65003, BGP_PFXV_STATE_NOT_FOUND, 0);
    TEST("192.0.2.128", 25, 65001, BGP_PFXV_STATE_NOT_FOUND, 0);

    puts("=== Re-add ROA; preserve unrelated cache entries again ===");
    int readd_ok = cached_update(&v, &roa, 1) == SUCCESS;
    int readd_selective_ok = (v.cache.count == 2 &&
                              v.cache.selectively_invalidated == 6 &&
                              v.cache.globally_invalidated == 0);
    TEST("198.51.100.0", 24, 65004, BGP_PFXV_STATE_NOT_FOUND, 1);
    TEST("192.0.2.0", 24, 65001, BGP_PFXV_STATE_VALID, 0);
    TEST("192.0.2.0", 24, 65003, BGP_PFXV_STATE_INVALID, 0);
    TEST("192.0.2.128", 25, 65001, BGP_PFXV_STATE_INVALID, 0);

    /* Additional correctness cases: overlapping covering authorizations.
     * Compare all cached results with a direct invocation of h2ROV.
     */
    int advanced_ok = 1;
#define CHECK_ORACLE(addr, len, asn, expected, hit) do { \
        ++total; \
        int result = check_with_oracle(&v, addr, len, asn, expected, hit); \
        passed += result; \
        if (!result) advanced_ok = 0; \
    } while (0)

    puts("=== Advanced tests: covering /16 ROA addition ===");
    CHECK_ORACLE("192.0.3.0", 24, 65020, BGP_PFXV_STATE_NOT_FOUND, 0);
    struct pdu_ipv4 parent = {0};
    char parent_addr[] = "192.0.0.0";
    init_pdu_v4(&parent, TROA_IPV4, parent_addr, 16, 24, 65020);
    unsigned long selective_before = v.cache.selectively_invalidated;
    if (cached_update(&v, &parent, 1) != SUCCESS) advanced_ok = 0;
    /* Before the parent update the cache holds 3 descendants of
     * 192.0.2.0/24 and one 192.0.3.0/24 entry. */
    if (v.cache.selectively_invalidated - selective_before != 4 ||
        v.cache.count != 2) {
        puts("FAIL: expected four descendant evictions and two retained entries");
        advanced_ok = 0;
    }
    CHECK_ORACLE("198.51.100.0", 24, 65004, BGP_PFXV_STATE_NOT_FOUND, 1);
    CHECK_ORACLE("203.0.113.0", 24, 65005, BGP_PFXV_STATE_NOT_FOUND, 1);
    CHECK_ORACLE("192.0.3.0", 24, 65020, BGP_PFXV_STATE_VALID, 0);
    CHECK_ORACLE("192.0.2.0", 24, 65020, BGP_PFXV_STATE_VALID, 0);
    CHECK_ORACLE("192.0.2.128", 25, 65001, BGP_PFXV_STATE_INVALID, 0);

    puts("=== Advanced tests: covering /16 ROA withdrawal ===");
    selective_before = v.cache.selectively_invalidated;
    if (cached_update(&v, &parent, 0) != SUCCESS) advanced_ok = 0;
    if (v.cache.selectively_invalidated - selective_before != 3 ||
        v.cache.count != 2) {
        puts("FAIL: expected three descendant evictions and two retained entries");
        advanced_ok = 0;
    }
    CHECK_ORACLE("203.0.113.0", 24, 65005, BGP_PFXV_STATE_NOT_FOUND, 1);
    CHECK_ORACLE("192.0.3.0", 24, 65020, BGP_PFXV_STATE_NOT_FOUND, 0);
    CHECK_ORACLE("192.0.2.0", 24, 65001, BGP_PFXV_STATE_VALID, 0);

    puts("=== Advanced tests: NotFound -> Valid -> NotFound ===");
    CHECK_ORACLE("198.51.100.0", 24, 65004, BGP_PFXV_STATE_NOT_FOUND, 1);
    struct pdu_ipv4 new_roa = {0};
    char new_addr[] = "198.51.100.0";
    init_pdu_v4(&new_roa, TROA_IPV4, new_addr, 24, 24, 65004);
    if (cached_update(&v, &new_roa, 1) != SUCCESS) advanced_ok = 0;
    CHECK_ORACLE("203.0.113.0", 24, 65005, BGP_PFXV_STATE_NOT_FOUND, 1);
    CHECK_ORACLE("198.51.100.0", 24, 65004, BGP_PFXV_STATE_VALID, 0);
    if (cached_update(&v, &new_roa, 0) != SUCCESS) advanced_ok = 0;
    CHECK_ORACLE("203.0.113.0", 24, 65005, BGP_PFXV_STATE_NOT_FOUND, 1);
    CHECK_ORACLE("198.51.100.0", 24, 65004, BGP_PFXV_STATE_NOT_FOUND, 0);
    printf("Advanced checks: %s\n", advanced_ok ? "PASS" : "FAIL");

    printf("Summary: validations=%d/%d before=%s withdrawal=%s "
           "selectivity=%s readd=%s readd_selectivity=%s\n",
           passed, total, before_ok ? "PASS" : "FAIL",
           remove_ok ? "PASS" : "FAIL", selective_ok ? "PASS" : "FAIL",
           readd_ok ? "PASS" : "FAIL",
           readd_selective_ok ? "PASS" : "FAIL");
    printf("Final counters: hits=%lu misses=%lu selective_invalidations=%lu "
           "global_invalidations=%lu evictions=%lu entries=%zu\n",
           v.cache.hits, v.cache.misses, v.cache.selectively_invalidated,
           v.cache.globally_invalidated, v.cache.evictions, v.cache.count);
    /* Upstream nLBS release has commented-out cleanup. The operating system
       will reclaim its memory when this standalone test process exits. */
    clear_all(&v.cache);
    int success = (passed == total && before_ok && remove_ok &&
                   selective_ok && readd_ok && readd_selective_ok && advanced_ok);
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
