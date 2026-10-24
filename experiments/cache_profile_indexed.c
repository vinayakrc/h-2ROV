/*
 * h2ROV Configuration C: selective invalidation of validation-result cache.
 * Standalone SINGLE-THREADED comparative MICROBENCHMARK.
 * Scalable pool variant: preallocates cache nodes and recycles them after eviction
 * Adds mode D: prefix-trie selective invalidation with per-prefix cache-entry lists.
 * Mode C retains the unchanged linear scan for an apples-to-apples comparison.
 * and invalidation. This isolates cache-allocation overhead.
 * Pool initialization is intentionally outside the timed section; its
 * one-time cost and reserved memory must be reported separately.
 * Derived from: experiments/cache_profile_pool.c
 * Extra CLI argument sets number of distinct routes.
 * Exactly 32 keys are affected by the ROA update for each route count.
 * Prefix trie nodes are inserted on demand and pruned when no longer needed.
 * Index maintenance is INCLUDED in the timed workload.
 * This is an isolated synthetic scalability benchmark, not production workload.
 *
 * Build from repository root:
 * gcc -std=gnu11 -O2 -I. experiments/cache_profile_indexed.c -L. -lhrov \
 *   -lrtr -lxxhash -lm -lpthread -o experiments/cache_profile_indexed
 *
 * Run: LD_LIBRARY_PATH="$PWD" ./experiments/cache_profile_indexed \
 *      A|B|C|D requests update_every capacity seed route_count
 *
 * Important: All authorization changes must pass through the wrappers.
 * Unknown record formats, invalid update metadata, or failed underlying
 * updates conservatively clear the entire cache. Real RTR reset/resync and
 * concurrency require additional handling before integration into a router.
 */
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "src/hrov_header.h"

#define BUCKETS 65537u
#define CAPACITY 8u

typedef struct {
    uint32_t asn;
    uint8_t masklen;
    struct lrtr_ip_addr prefix;
} CacheKey;

typedef struct PrefixNode PrefixNode;

typedef struct CacheEntry {
    CacheKey key;
    enum pfxv_state value;
    struct CacheEntry *bucket_next;
    struct CacheEntry *older, *newer;
    /* Doubly linked membership in one EXACT network-prefix trie node. */
    struct CacheEntry *index_prev, *index_next;
    PrefixNode *index_owner;
} CacheEntry;

struct PrefixNode {
    PrefixNode *parent, *child[2];
    CacheEntry *entries; /* Different origin ASNs can share this prefix. */
    uint8_t parent_branch, family;
};

typedef struct {
    CacheEntry *bucket[BUCKETS];
    CacheEntry *lru, *mru;
    size_t count, capacity;
    unsigned long hits, misses, evictions;
    unsigned long selectively_invalidated, globally_invalidated;
    /* Preallocated fixed-capacity cache entries; no per-miss malloc/free. */
    CacheEntry *pool, *free_entries;
    size_t pool_used;
    /* Mode D only: one binary trie per AFI and bounded removal worklist. */
    int use_index;
    PrefixNode *roots[2];
    CacheEntry **worklist;
    size_t index_nodes, peak_index_nodes, visited_index_nodes;
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

/* The upstream RTRlib IPv4/IPv6 address representation stores network
 * addresses in 32-bit words compatible with top_bits(), as used by the
 * original cache and its validated prefix-containment tests.
 */
static unsigned network_bit(const struct lrtr_ip_addr *p, unsigned bit)
{
    if (p->ver == LRTR_IPV4)
        return (p->u.addr4.addr >> (31u - bit)) & 1u;
    return (p->u.addr6.addr[bit / 32u] >> (31u - (bit % 32u))) & 1u;
}

static PrefixNode *create_node(Cache *c, PrefixNode *parent,
                               unsigned branch, unsigned family)
{
    PrefixNode *n = calloc(1, sizeof(*n));
    if (!n) return NULL;
    n->parent = parent;
    n->parent_branch = (uint8_t)branch;
    n->family = (uint8_t)family;
    ++c->index_nodes;
    if (c->index_nodes > c->peak_index_nodes)
        c->peak_index_nodes = c->index_nodes;
    return n;
}

/* Delete empty leaves, working up to the first useful ancestor. This bounds
 * retained index memory to the CURRENT cache contents rather than all keys
 * ever encountered, even after heavy eviction/invalidation churn. */
static void prune_empty_nodes(Cache *c, PrefixNode *node)
{
    while (node && !node->entries && !node->child[0] && !node->child[1]) {
        PrefixNode *parent = node->parent;
        if (parent)
            parent->child[node->parent_branch] = NULL;
        else
            c->roots[node->family] = NULL;
        free(node);
        --c->index_nodes;
        node = parent;
    }
}

/* Returns 0 on allocation failure; the caller can omit the cache insertion
 * without affecting route-validation correctness. */
static int prefix_index_add(Cache *c, CacheEntry *entry)
{
    const unsigned family = entry->key.prefix.ver == LRTR_IPV4 ? 0u : 1u;
    PrefixNode *node = c->roots[family];
    if (!node) {
        node = create_node(c, NULL, 0u, family);
        if (!node) return 0;
        c->roots[family] = node;
    }
    for (unsigned bit = 0; bit < entry->key.masklen; ++bit) {
        unsigned branch = network_bit(&entry->key.prefix, bit);
        if (!node->child[branch]) {
            PrefixNode *next = create_node(c, node, branch, family);
            if (!next) {
                prune_empty_nodes(c, node);
                return 0;
            }
            node->child[branch] = next;
        }
        node = node->child[branch];
    }
    entry->index_owner = node;
    entry->index_prev = NULL;
    entry->index_next = node->entries;
    if (node->entries) node->entries->index_prev = entry;
    node->entries = entry;
    return 1;
}

static void prefix_index_remove(Cache *c, CacheEntry *entry)
{
    PrefixNode *node = entry->index_owner;
    if (!node) return;
    if (entry->index_prev) entry->index_prev->index_next = entry->index_next;
    else node->entries = entry->index_next;
    if (entry->index_next) entry->index_next->index_prev = entry->index_prev;
    entry->index_owner = NULL;
    entry->index_prev = entry->index_next = NULL;
    prune_empty_nodes(c, node);
}

/* Collect all entries in the updated-prefix subtree BEFORE removing any;
 * otherwise pruning could free trie nodes during recursive traversal.
 * The worklist is bounded by the cache capacity and allocated outside the
 * timed benchmark loop. */
static void collect_subtree(Cache *c, PrefixNode *node, size_t *found)
{
    if (!node) return;
    ++c->visited_index_nodes;
    for (CacheEntry *e = node->entries; e; e = e->index_next) {
        if (*found >= c->capacity) {
            fputs("Fatal: prefix-index worklist overflow\n", stderr);
            abort();
        }
        c->worklist[(*found)++] = e;
    }
    collect_subtree(c, node->child[0], found);
    collect_subtree(c, node->child[1], found);
}

static void discard(Cache *c, CacheEntry *e)
{
    size_t b = bucket_for(&e->key);
    CacheEntry **pp = &c->bucket[b];
    while (*pp && *pp != e) pp = &(*pp)->bucket_next;
    if (*pp) *pp = e->bucket_next;
    unlink_lru(c, e);
    if (c->use_index) prefix_index_remove(c, e);
    /* Place removed node on the reusable free list. */
    e->bucket_next = c->free_entries;
    c->free_entries = e;
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

/* Mode D: descend through P's address bits, then visit ONLY the cached
 * subtrie covered by P. Ignore ASN and maxLength: routes with any origin,
 * including routes longer than maxLength, may change ROV classification.
 * Complexity: O(prefix_length + visited_subtree_nodes + affected_entries).
 */
static size_t selectively_clear_index(Cache *c,
                                    const struct lrtr_ip_addr *updated,
                                    uint8_t updated_len)
{
    unsigned family = updated->ver == LRTR_IPV4 ? 0u : 1u;
    PrefixNode *node = c->roots[family];
    for (unsigned bit = 0; node && bit < updated_len; ++bit)
        node = node->child[network_bit(updated, bit)];
    size_t found = 0;
    if (node) collect_subtree(c, node, &found);
    for (size_t i = 0; i < found; ++i)
        discard(c, c->worklist[i]);
    c->selectively_invalidated += found;
    return found;
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
    if (c->count == c->capacity) {
        discard(c, c->lru);
        ++c->evictions;
    }
    CacheEntry *e = NULL;
    if (c->free_entries) {
        e = c->free_entries;
        c->free_entries = e->bucket_next;
    } else if (c->pool_used < c->capacity) {
        e = &c->pool[c->pool_used++];
    } else {
        /* No space available; preserve correctness by skipping caching. */
        return;
    }
    memset(e, 0, sizeof(*e));
    e->key = *key;
    e->value = value;
    if (c->use_index && !prefix_index_add(c, e)) {
        /* Recycle node; never cache a key that is absent from the index. */
        e->bucket_next = c->free_entries;
        c->free_entries = e;
        return;
    }
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

/* A: original h2ROV; B: global LRU; C: linear selective; D: indexed selective.
 * Same deterministic workload and authorizations in all three modes.
 * Times exclude initialization and input generation; include validation,
 * cache operations, and authorization add/remove update processing.
 * A single process runs one mode to avoid upstream h2ROV cleanup issues.
 */
#define DEFAULT_NUM_ROUTES 128u
#define MAX_ROUTES 65536u
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

static void populate_routes(Route *routes, size_t num_routes)
{
    for (size_t i = 0; i < num_routes; ++i) {
        char ip[32];
        /* First 32 keys are affected; the rest are unaffected. */
        if (i < 32)
            snprintf(ip, sizeof(ip), "192.0.%u.0", (unsigned)i);
        else
            snprintf(ip, sizeof(ip), "10.%u.%u.0",
                     (unsigned)((i - 32) / 256),
                     (unsigned)((i - 32) % 256));
        memset(&routes[i], 0, sizeof(routes[i]));
        lrtr_ip_str_to_addr(ip, &routes[i].addr);
        routes[i].len = 24;
        routes[i].asn = (i < 32 ? ((i & 1) ? 65003u : 65001u) : 65004u);
    }
}

/*
 * Lightweight phase profiling. Only update events are timestamped;
 * per-route validation calls are NOT individually timed to avoid adding
 * two clock_gettime calls to each route validation.
 *
 * Initial authorization setup is deliberately excluded: counters are
 * reset immediately before the main timed request loop.
 */
static double prof_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static double prof_roa_seconds = 0.0;
static double prof_invalidation_seconds = 0.0;
static size_t prof_update_events = 0;

static int do_update(CachedValidator *v, const struct pdu_ipv4 *record,
                     char mode, int is_add)
{
    double update_start = prof_now();
    int rc = is_add ? v->original.rov_pfx_add(v->original.ht, (void *)record)
                    : v->original.rov_pfx_rm(v->original.ht, (void *)record);
    double invalidation_start = prof_now();
    if (mode == 'B') {
        clear_all(&v->cache);
    } else if (mode == 'C' || mode == 'D') {
        if (rc == SUCCESS) {
            struct lrtr_ip_addr changed;
            uint8_t len = 0;
            if (updated_prefix_from_record(record, &changed, &len)) {
                if (mode == 'D')
                    selectively_clear_index(&v->cache, &changed, len);
                else
                    selectively_clear(&v->cache, &changed, len);
            }
            else
                clear_all(&v->cache);
        } else {
            clear_all(&v->cache);
        }
    }
    double update_end = prof_now();
    prof_roa_seconds += invalidation_start - update_start;
    prof_invalidation_seconds += update_end - invalidation_start;
    ++prof_update_events;
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
    if (argc < 2 || argv[1][0] < 'A' || argv[1][0] > 'D' || argv[1][1]) {
        fprintf(stderr, "Usage: %s A|B|C|D [requests >= 1] [update_every >= 1] [capacity >= 1] [seed >= 1] [route_count 32..65536]\n", argv[0]);
        return 2;
    }
    char mode = argv[1][0];
    size_t requests = argc > 2 ? (size_t)strtoull(argv[2], NULL, 10) : DEFAULT_REQUESTS;
    size_t update_every = argc > 3 ? (size_t)strtoull(argv[3], NULL, 10) : DEFAULT_UPDATE_EVERY;
    size_t capacity = argc > 4 ? (size_t)strtoull(argv[4], NULL, 10) : DEFAULT_NUM_ROUTES;
    uint32_t seed = argc > 5 ? (uint32_t)strtoul(argv[5], NULL, 10) : 12345u;
    size_t num_routes = argc > 6 ? (size_t)strtoull(argv[6], NULL, 10) : DEFAULT_NUM_ROUTES;
    if (!requests || !update_every || !capacity || !seed || requests > 20000000u || capacity > 100000u ||
        num_routes < 32u || num_routes > MAX_ROUTES) {
        fputs("Invalid benchmark parameters\n", stderr);
        return 2;
    }

    /* Exactly 32 route keys lie within the changed 192.0.0.0/16 ROA.
       All other unique /24 route keys lie in 10.0.0.0/8. */
    Route *routes = calloc(num_routes, sizeof(*routes));
    uint32_t *indices = malloc(requests * sizeof(*indices));
    if (!routes || !indices) {
        perror("allocate benchmark workload");
        free(routes);
        free(indices);
        return 1;
    }
    populate_routes(routes, num_routes);
    /* Workload is generated outside the timed section. */
    uint32_t rand_state = seed;
    for (size_t i = 0; i < requests; ++i)
        indices[i] = next_random(&rand_state) % num_routes;

    CachedValidator v = {0};
    v.original = hrov_nlbs_binary;
    v.original.wide_threshold = 5;
    v.cache.capacity = capacity;
    v.cache.use_index = mode == 'D';
    if (v.cache.use_index) {
        v.cache.worklist = malloc(capacity * sizeof(*v.cache.worklist));
        if (!v.cache.worklist) {
            perror("prefix-index worklist");
            free(routes);
            free(indices);
            return 1;
        }
    }
    v.cache.pool = calloc(capacity, sizeof(*v.cache.pool));
    if (!v.cache.pool) {
        perror("cache pool calloc");
        free(indices);
        return 1;
    }
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
    /* Ignore the initial ROA insertion, which occurs before the timed loop. */
    prof_roa_seconds = 0.0;
    prof_invalidation_seconds = 0.0;
    prof_update_events = 0;
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
    /* The residual includes route validations, cache operations, loop
       bookkeeping, digest computation, and timing overhead. */
    double residual_seconds = elapsed - prof_roa_seconds - prof_invalidation_seconds;
    double avg_roa_update_us = prof_update_events
        ? 1e6 * prof_roa_seconds / (double)prof_update_events : 0.0;
    double avg_invalidation_us = prof_update_events
        ? 1e6 * prof_invalidation_seconds / (double)prof_update_events : 0.0;
    printf("mode,requests,update_every,capacity,seed,route_count,seconds,validations_per_second,hits,misses,evictions,selectively_invalidated,globally_invalidated,digest,roa_update_seconds,invalidation_seconds,validation_and_loop_seconds,update_events,avg_roa_update_us,avg_invalidation_us,index_peak_nodes,index_visited_nodes,index_peak_bytes_est\n");
    printf("%c,%zu,%zu,%zu,%" PRIu32 ",%zu,%.9f,%.3f,%lu,%lu,%lu,%lu,%lu,%" PRIu64 ",%.9f,%.9f,%.9f,%zu,%.6f,%.6f,%zu,%zu,%zu\n",
           mode, requests, update_every, capacity, seed, num_routes, elapsed,
           (double)requests / elapsed,
           v.cache.hits, v.cache.misses, v.cache.evictions,
           v.cache.selectively_invalidated, v.cache.globally_invalidated,
           digest, prof_roa_seconds, prof_invalidation_seconds,
           residual_seconds, prof_update_events,
           avg_roa_update_us, avg_invalidation_us,
           v.cache.peak_index_nodes, v.cache.visited_index_nodes,
           v.cache.peak_index_nodes * sizeof(PrefixNode)
               + (v.cache.use_index ? 4 * capacity * sizeof(void *) : 0));
    free(indices);
    free(routes);
    clear_all(&v.cache);
    free(v.cache.pool);
    free(v.cache.worklist);
    if (v.cache.index_nodes != 0) {
        fprintf(stderr, "INDEX LEAK: %zu trie nodes remain\n", v.cache.index_nodes);
        return 1;
    }
    /* No h2ROV release: upstream implementation's cleanup is incomplete. */
    return 0;
}
