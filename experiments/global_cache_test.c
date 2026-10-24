/*
 * h2ROV Configuration B: standalone LRU validation-result cache with
 * global invalidation on authorization updates.
 *
 * This is a single-threaded correctness prototype; do not yet use it for
 * FRRouting integration or performance claims.
 * Build from the h-2ROV repository root:
 *   gcc -std=gnu11 -O0 -g -Wall -Wextra -I. \
 *     experiments/global_cache_test.c -L. -lhrov \
 *     -lrtr -lxxhash -lm -lpthread -o experiments/global_cache_test
 * Run:
 *   LD_LIBRARY_PATH="$PWD" ./experiments/global_cache_test
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/hrov_header.h"

#define BUCKETS 257u
#define CACHE_CAPACITY 3u

typedef struct {
    uint32_t asn;
    uint8_t masklen;
    struct lrtr_ip_addr prefix;
} CacheKey;

typedef struct CacheEntry {
    CacheKey key;
    enum pfxv_state value;
    struct CacheEntry *bucket_next;
    struct CacheEntry *older;
    struct CacheEntry *newer;
} CacheEntry;

typedef struct {
    CacheEntry *bucket[BUCKETS];
    CacheEntry *lru; /* least recently used */
    CacheEntry *mru; /* most recently used */
    size_t count;
    size_t capacity;
    unsigned long hits, misses, evictions, invalidated;
} ValidationCache;

/* Hash *defined fields*, never struct padding bytes. */
static uint32_t hash_bytes(uint32_t h, const void *buffer, size_t len)
{
    const unsigned char *p = buffer;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= UINT32_C(16777619);
    }
    return h;
}

static size_t bucket_for(const CacheKey *key)
{
    uint32_t h = UINT32_C(2166136261);
    h = hash_bytes(h, &key->asn, sizeof(key->asn));
    h = hash_bytes(h, &key->masklen, sizeof(key->masklen));
    h = hash_bytes(h, &key->prefix.ver, sizeof(key->prefix.ver));
    if (key->prefix.ver == LRTR_IPV4)
        h = hash_bytes(h, &key->prefix.u.addr4.addr,
                       sizeof(key->prefix.u.addr4.addr));
    else
        h = hash_bytes(h, key->prefix.u.addr6.addr,
                       sizeof(key->prefix.u.addr6.addr));
    return h % BUCKETS;
}

static int same_key(const CacheKey *a, const CacheKey *b)
{
    if (a->asn != b->asn || a->masklen != b->masklen ||
        a->prefix.ver != b->prefix.ver)
        return 0;
    if (a->prefix.ver == LRTR_IPV4)
        return a->prefix.u.addr4.addr == b->prefix.u.addr4.addr;
    return memcmp(a->prefix.u.addr6.addr, b->prefix.u.addr6.addr,
                  sizeof(a->prefix.u.addr6.addr)) == 0;
}

static CacheKey make_key(uint32_t asn, const struct lrtr_ip_addr *prefix,
                         uint8_t masklen)
{
    CacheKey key;
    memset(&key, 0, sizeof(key));
    key.asn = asn;
    key.masklen = masklen;
    key.prefix.ver = prefix->ver;
    if (prefix->ver == LRTR_IPV4)
        key.prefix.u.addr4.addr = prefix->u.addr4.addr;
    else
        memcpy(key.prefix.u.addr6.addr, prefix->u.addr6.addr,
               sizeof(key.prefix.u.addr6.addr));
    return key;
}

static void unlink_lru(ValidationCache *c, CacheEntry *e)
{
    if (e->older) e->older->newer = e->newer;
    else c->lru = e->newer;
    if (e->newer) e->newer->older = e->older;
    else c->mru = e->older;
    e->older = e->newer = NULL;
}

static void append_mru(ValidationCache *c, CacheEntry *e)
{
    e->older = c->mru;
    e->newer = NULL;
    if (c->mru) c->mru->newer = e;
    else c->lru = e;
    c->mru = e;
}

static void discard_entry(ValidationCache *c, CacheEntry *e)
{
    size_t b = bucket_for(&e->key);
    CacheEntry **pp = &c->bucket[b];
    while (*pp && *pp != e) pp = &(*pp)->bucket_next;
    if (*pp) *pp = e->bucket_next;
    unlink_lru(c, e);
    free(e);
    --c->count;
}

static void clear_cache(ValidationCache *c)
{
    c->invalidated += (unsigned long)c->count;
    while (c->lru) discard_entry(c, c->lru);
}

static int cache_lookup(ValidationCache *c, const CacheKey *key,
                        enum pfxv_state *out)
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

static void cache_insert(ValidationCache *c, const CacheKey *key,
                         enum pfxv_state value)
{
    if (!c->capacity) return;
    if (c->count == c->capacity) {
        discard_entry(c, c->lru);
        ++c->evictions;
    }
    CacheEntry *e = calloc(1, sizeof(*e));
    if (!e) return; /* Cache allocation failure must not break ROV. */
    e->key = *key;
    e->value = value;
    size_t b = bucket_for(key);
    e->bucket_next = c->bucket[b];
    c->bucket[b] = e;
    append_mru(c, e);
    ++c->count;
}

typedef struct {
    struct rov_algo_t original;
    ValidationCache cache;
} CachedValidator;

static int cached_validate(CachedValidator *v, uint32_t asn,
                           const struct lrtr_ip_addr *prefix, uint8_t masklen,
                           enum pfxv_state *state)
{
    CacheKey key = make_key(asn, prefix, masklen);
    if (cache_lookup(&v->cache, &key, state)) return SUCCESS;
    int rc = v->original.rov_pfx_validate(v->original.ht, asn, prefix,
                                           masklen, state);
    if (rc == SUCCESS) cache_insert(&v->cache, &key, *state);
    return rc;
}

static int cached_add(CachedValidator *v, void *record)
{
    int rc = v->original.rov_pfx_add(v->original.ht, record);
    /* Clear even on error: partial updates cannot leave old cached results. */
    clear_cache(&v->cache);
    return rc;
}

static int cached_remove(CachedValidator *v, void *record)
{
    int rc = v->original.rov_pfx_rm(v->original.ht, record);
    clear_cache(&v->cache);
    return rc;
}

static const char *state_name(enum pfxv_state state)
{
    switch (state) {
    case BGP_PFXV_STATE_VALID: return "VALID";
    case BGP_PFXV_STATE_INVALID: return "INVALID";
    case BGP_PFXV_STATE_NOT_FOUND: return "NOTFOUND";
    default: return "UNKNOWN";
    }
}

static int check(CachedValidator *v, const char *address, uint8_t len,
                 uint32_t asn, enum pfxv_state expected)
{
    struct lrtr_ip_addr prefix;
    memset(&prefix, 0, sizeof(prefix));
    lrtr_ip_str_to_addr(address, &prefix);
    enum pfxv_state actual = BGP_PFXV_STATE_NOT_FOUND;
    int rc = cached_validate(v, asn, &prefix, len, &actual);
    int ok = (rc == SUCCESS && actual == expected);
    printf("%-15s/%u AS%-6u %-8s expected %-8s %s\n", address,
           (unsigned)len, asn, state_name(actual), state_name(expected),
           ok ? "PASS" : "FAIL");
    return ok;
}

int main(void)
{
    CachedValidator v = {0};
    v.original = hrov_nlbs_binary;
    v.original.wide_threshold = 5;
    v.cache.capacity = CACHE_CAPACITY;
    v.original.rov_init(&v.original);
    if (!v.original.ht) {
        fputs("h2ROV initialization failed\n", stderr);
        return EXIT_FAILURE;
    }

    struct pdu_ipv4 authorization = {0};
    char auth_addr[] = "192.0.2.0";
    init_pdu_v4(&authorization, TROA_IPV4, auth_addr, 24, 24, 65001);
    if (cached_add(&v, &authorization) != SUCCESS) {
        fputs("authorization add failed\n", stderr);
        return EXIT_FAILURE;
    }

    int passed = 0, total = 0;
    puts("=== Before withdrawal ===");
#define TEST(addr, len, asn, expected) do { \
        ++total; passed += check(&v, addr, len, asn, expected); \
    } while (0)
    TEST("192.0.2.0", 24, 65001, BGP_PFXV_STATE_VALID);      /* miss */
    TEST("192.0.2.0", 24, 65001, BGP_PFXV_STATE_VALID);      /* hit */
    TEST("192.0.2.0", 24, 65003, BGP_PFXV_STATE_INVALID);    /* miss */
    TEST("198.51.100.0", 24, 65004, BGP_PFXV_STATE_NOT_FOUND); /* miss */
    TEST("198.51.100.0", 24, 65004, BGP_PFXV_STATE_NOT_FOUND); /* hit */
    /* Fourth unique key triggers the LRU eviction (capacity = 3). */
    TEST("203.0.113.0", 24, 65005, BGP_PFXV_STATE_NOT_FOUND);
    printf("Cache before withdrawal: hits=%lu misses=%lu evictions=%lu entries=%zu\n",
           v.cache.hits, v.cache.misses, v.cache.evictions, v.cache.count);
    int stats_ok = (v.cache.hits == 2 && v.cache.misses == 4 &&
                    v.cache.evictions == 1 && v.cache.count == 3);

    puts("=== Authorization withdrawal ===");
    if (cached_remove(&v, &authorization) != SUCCESS) {
        fputs("authorization remove failed\n", stderr);
        clear_cache(&v.cache);
        return EXIT_FAILURE;
    }
    int cleared_ok = (v.cache.count == 0 && v.cache.invalidated == 3);
    printf("Cache cleared=%s invalidated=%lu\n",
           cleared_ok ? "YES" : "NO", v.cache.invalidated);
    TEST("192.0.2.0", 24, 65001, BGP_PFXV_STATE_NOT_FOUND);
    TEST("192.0.2.0", 24, 65003, BGP_PFXV_STATE_NOT_FOUND);

    printf("Result: %d/%d validations passed; cache counters %s; invalidation %s\n",
           passed, total, stats_ok ? "PASS" : "FAIL",
           cleared_ok ? "PASS" : "FAIL");
    clear_cache(&v.cache);
    return (passed == total && stats_ok && cleared_ok) ? EXIT_SUCCESS : EXIT_FAILURE;
}
