/* Regression tests for mode-D and mode-E prefix trie internals.
 * Compile from h-2ROV root:
 * gcc -std=gnu11 -O2 -I. experiments/indexed_cache_regression.c \
 *   -L. -lhrov -lrtr -lxxhash -lm -lpthread \
 *   -o experiments/indexed_cache_regression
 * Run with LD_LIBRARY_PATH="$PWD" ./experiments/indexed_cache_regression
 *
 * The include intentionally keeps the tested cache routines in the SAME
 * translation unit as the benchmark; no duplicate implementation to drift.
 */
#define main indexed_benchmark_main
#include "cache_profile_triepool.c"
#undef main

static int assertions = 0;
static int test_use_node_pool = 0;
#define REQUIRE(condition, message) do {                                      \
    ++assertions;                                                             \
    if (!(condition)) {                                                       \
        fprintf(stderr, "FAIL at line %d: %s\n", __LINE__, message);        \
        exit(EXIT_FAILURE);                                                   \
    }                                                                         \
} while (0)

static void init_cache(Cache *c, size_t capacity)
{
    memset(c, 0, sizeof(*c));
    c->capacity = capacity;
    c->use_index = 1;
    c->use_node_pool = test_use_node_pool;
    c->pool = calloc(capacity, sizeof(*c->pool));
    c->worklist = calloc(capacity, sizeof(*c->worklist));
    REQUIRE(c->pool && c->worklist, "cache buffers allocated");
}

static void dispose_cache(Cache *c)
{
    clear_all(c);
    REQUIRE(c->index_nodes == 0, "trie must be completely pruned");
    REQUIRE(c->count == 0, "cache must be empty");
    if (test_use_node_pool) {
        REQUIRE(c->node_recycles > 0, "pool returned trie nodes after pruning");
        REQUIRE(c->node_freelist_count > 0, "pool holds inactive trie nodes");
    }
    free_recycled_nodes(c);
    REQUIRE(c->node_freelist == NULL && c->node_freelist_count == 0,
            "recycled nodes released at shutdown");
    free(c->worklist);
    free(c->pool);
}

static CacheKey v4key(const char *ip, uint8_t mask, uint32_t asn)
{
    struct lrtr_ip_addr a;
    lrtr_ip_str_to_addr(ip, &a);
    return make_key(asn, &a, mask);
}

static int contains(Cache *c, const CacheKey *key)
{
    for (CacheEntry *e = c->bucket[bucket_for(key)]; e; e = e->bucket_next)
        if (same_key(key, &e->key)) return 1;
    return 0;
}

static size_t invalidate_v4(Cache *c, const char *ip, uint8_t len)
{
    struct lrtr_ip_addr a;
    lrtr_ip_str_to_addr(ip, &a);
    return selectively_clear_index(c, &a, len);
}

static void check_ipv4_covering_and_asn(void)
{
    Cache *c = calloc(1, sizeof(*c));
    REQUIRE(c != NULL, "allocate test cache");
    init_cache(c, 6);
    CacheKey keys[] = {
        v4key("192.0.2.0", 24, 65001),
        v4key("192.0.2.0", 24, 65003),
        v4key("192.0.2.128", 25, 65001), /* longer than maxLength 24 */
        v4key("192.0.3.0", 24, 65020),
        v4key("198.51.100.0", 24, 65004),
    };
    for (size_t i=0; i<5; ++i)
        insert(c, &keys[i], BGP_PFXV_STATE_NOT_FOUND);
    REQUIRE(c->count == 5, "five distinct route-origin keys cached");
    REQUIRE(invalidate_v4(c, "192.0.2.0", 25) == 0,
            "/25 ROA does not affect cached /24 or other /25");
    REQUIRE(invalidate_v4(c, "192.0.2.0", 24) == 3,
            "/24 affects both ASNs and its more-specific /25");
    REQUIRE(c->count == 2, "unrelated entries survive selective clear");
    for (size_t i = 0; i < 3; ++i)
        REQUIRE(!contains(c, &keys[i]), "affected key removed");
    for (size_t i = 3; i < 5; ++i)
        REQUIRE(contains(c, &keys[i]), "unaffected key preserved");
    for (size_t i=0; i<3; ++i)
        insert(c, &keys[i], BGP_PFXV_STATE_INVALID);
    REQUIRE(invalidate_v4(c, "192.0.0.0", 16) == 4,
            "/16 withdraw invalidates all /24 and /25 descendants");
    REQUIRE(contains(c, &keys[4]), "unrelated prefix survives /16 update");
    REQUIRE(c->count == 1, "one unrelated cached entry remains");
    dispose_cache(c);
    free(c);
}

static void check_lru_recycling_and_pruning(void)
{
    Cache *c = calloc(1, sizeof(*c));
    REQUIRE(c != NULL, "allocate eviction cache");
    init_cache(c, 2);
    CacheKey first = v4key("192.0.2.0",24,1);
    CacheKey second = v4key("198.51.100.0",24,2);
    CacheKey third = v4key("203.0.113.0",24,3);
    insert(c,&first,BGP_PFXV_STATE_NOT_FOUND);
    insert(c,&second,BGP_PFXV_STATE_NOT_FOUND);
    insert(c,&third,BGP_PFXV_STATE_NOT_FOUND);
    REQUIRE(c->evictions == 1, "eviction triggered by third insert");
    REQUIRE(!contains(c,&first), "LRU victim removed from hash and index");
    REQUIRE(contains(c,&second) && contains(c,&third), "survivors intact");
    REQUIRE(invalidate_v4(c,"192.0.2.0",24) == 0,
            "removed LRU key is absent from prefix index");
    REQUIRE(invalidate_v4(c,"198.51.100.0",24) == 1,
            "selective invalidation after eviction");
    insert(c,&first,BGP_PFXV_STATE_VALID);
    REQUIRE(contains(c,&first), "recycled cache entry is indexable");
    REQUIRE(c->count == 2, "cache count tracks reused entries");
    dispose_cache(c);
    free(c);
}

static void check_ipv6_prefix_bits(void)
{
    Cache *c = calloc(1, sizeof(*c));
    REQUIRE(c != NULL, "allocate IPv6 cache");
    init_cache(c, 3);
    struct lrtr_ip_addr p = {0}, update = {0};
    p.ver = LRTR_IPV6;
    p.u.addr6.addr[0] = UINT32_C(0x20010db8);
    p.u.addr6.addr[1] = UINT32_C(0x00010000);
    CacheKey a = make_key(65001, &p, 48);
    CacheKey b = make_key(65002, &p, 48);
    struct lrtr_ip_addr other = p;
    other.u.addr6.addr[0] = UINT32_C(0x20010db9);
    CacheKey outside = make_key(65001, &other, 48);
    insert(c, &a, BGP_PFXV_STATE_VALID);
    insert(c, &b, BGP_PFXV_STATE_INVALID);
    insert(c, &outside, BGP_PFXV_STATE_NOT_FOUND);
    update.ver = LRTR_IPV6;
    update.u.addr6.addr[0] = UINT32_C(0x20010db8);
    REQUIRE(selectively_clear_index(c, &update, 32) == 2,
            "IPv6 /32 covers two cached /48 keys with different ASNs");
    REQUIRE(!contains(c,&a) && !contains(c,&b), "IPv6 descendants removed");
    REQUIRE(contains(c,&outside), "different IPv6 /32 remains cached");
    dispose_cache(c);
    free(c);
}

/* Stress repeated eviction, reuse and index invalidation across prefixes. */
static void check_trie_node_recycling_stress(void)
{
    Cache *c = calloc(1, sizeof(*c));
    REQUIRE(c != NULL, "allocate stress cache");
    init_cache(c, 2);
    CacheKey keys[] = {
        v4key("192.0.2.0", 24, 65001),
        v4key("198.51.100.0", 24, 65002),
        v4key("203.0.113.0", 24, 65003),
    };
    for (size_t i = 0; i < 1000; ++i) {
        insert(c, &keys[i % 3], BGP_PFXV_STATE_NOT_FOUND);
        REQUIRE(c->count <= 2, "capacity respected under recycling");
    }
    REQUIRE(c->evictions == 998, "expected 998 repeated evictions");
    REQUIRE(c->count == 2, "cache filled under stress");
    REQUIRE(invalidate_v4(c, "0.0.0.0", 0) == 2,
            "IPv4 /0 invalidates every cached entry");
    REQUIRE(c->index_nodes == 0, "all active trie nodes removed after /0");
    if (test_use_node_pool) {
        REQUIRE(c->node_reuses > 0, "reused trie nodes during churn");
        REQUIRE(c->node_freelist_count > 0, "inactive nodes available");
        /* Only three different /24s are used, so allocation stays bounded. */
        REQUIRE(c->node_new_allocations < 150,
                "pool prevents per-miss trie-node allocation");
    }
    dispose_cache(c);
    free(c);
}

int main(void)
{
    for (int pooled = 0; pooled <= 1; ++pooled) {
        test_use_node_pool = pooled;
        check_ipv4_covering_and_asn();
        check_lru_recycling_and_pruning();
        check_ipv6_prefix_bits();
        check_trie_node_recycling_stress();
    }
    printf("Prefix-index D/E regression: PASS (%d assertions)\n", assertions);
    return 0;
}
