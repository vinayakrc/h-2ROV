/*
 * End-to-end IPv6 validation-cache regression against the real h2ROV library.
 * Tests C (linear), D (indexed), E (indexed + node reuse) in separate runs.
 * Includes the *existing* benchmark C source to exercise exactly its cache
 * code; the original benchmark main is renamed and never executed.
 *
 * Build from h-2ROV repository root:
 *   gcc -std=gnu11 -O0 -g -I. experiments/ipv6_cached_regression.c \
 *       -L. -lhrov -lrtr -lxxhash -lm -lpthread \
 *       -o experiments/ipv6_cached_regression
 * Run: LD_LIBRARY_PATH="$PWD" ./experiments/ipv6_cached_regression C|D|E
 *
 * This is a single-threaded prototype test, not an RTR/concurrency test.
 */
#define main h2rov_benchmark_main_not_used
#include "cache_profile_triepool.c"
#undef main

static unsigned checks, failures;

static void assertion(int ok, const char *message)
{
    ++checks;
    if (!ok) {
        ++failures;
        fprintf(stderr, "FAIL: %s\n", message);
    }
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

typedef struct {
    const char *name;
    const char *address;
    uint8_t length;
    uint32_t asn;
    struct lrtr_ip_addr addr;
} Case;

/* These are all distinct keys, including ASNs sharing the same IPv6 prefix. */
static Case cases[] = {
    {"parent",        "2001:db8:100::",     48, 65001, {0}},
    {"child-AS65001", "2001:db8:100:1::",   64, 65001, {0}},
    {"child-AS65003", "2001:db8:100:1::",   64, 65003, {0}},
    {"beyond-maxlen", "2001:db8:100:1::",   65, 65001, {0}},
    {"sibling",       "2001:db8:100:2::",   64, 65001, {0}},
    {"unrelated-v6",  "2001:db8:200::",     48, 65004, {0}},
    {"unrelated-v4",  "198.51.100.0",        24, 65077, {0}},
    {"child-AS65099", "2001:db8:100:1::",   64, 65099, {0}},
    {"ipv6-/128",    "2001:db8:100:1::",  128, 65001, {0}},
    {"notfound-v4",  "203.0.113.0",         24, 65088, {0}},
    {"broader-/47",  "2001:db8:100::",     47, 65001, {0}},
};
#define NUM_CASES (sizeof(cases) / sizeof(cases[0]))

static const enum pfxv_state N = BGP_PFXV_STATE_NOT_FOUND;
static const enum pfxv_state V = BGP_PFXV_STATE_VALID;
static const enum pfxv_state I = BGP_PFXV_STATE_INVALID;

static int key_present(const Cache *c, const Case *r)
{
    CacheKey key = make_key(r->asn, &r->addr, r->length);
    for (const CacheEntry *e = c->bucket[bucket_for(&key)]; e;
         e = e->bucket_next)
        if (same_key(&e->key, &key)) return 1;
    return 0;
}

/* Check every validation twice; the second call must hit the cache. */
static void check_stage(CachedValidator *v, const char *stage,
                        const enum pfxv_state expected[NUM_CASES])
{
    for (size_t i = 0; i < NUM_CASES; ++i) {
        Case *r = &cases[i];
        unsigned long old_hits = v->cache.hits;
        enum pfxv_state got = N;
        int rc = cached_validate(v, r->asn, &r->addr, r->length, &got);
        int ok = rc == SUCCESS && got == expected[i];
        char message[180];
        snprintf(message, sizeof(message), "%s: %s first validation expected %s got %s rc=%d",
                 stage, r->name, state_name(expected[i]), state_name(got), rc);
        assertion(ok, message);

        got = N;
        rc = cached_validate(v, r->asn, &r->addr, r->length, &got);
        snprintf(message, sizeof(message), "%s: %s repeated validation expected %s got %s rc=%d",
                 stage, r->name, state_name(expected[i]), state_name(got), rc);
        assertion(rc == SUCCESS && got == expected[i], message);
        snprintf(message, sizeof(message), "%s: %s repeated validation hit cache",
                 stage, r->name);
        assertion(v->cache.hits >= old_hits + 1, message);
    }
    assertion(v->cache.count == NUM_CASES, "all test keys retained after warming");
    printf("Stage %-19s PASS-CHECKED: cache entries=%zu, hits=%lu, misses=%lu\n",
           stage, v->cache.count, v->cache.hits, v->cache.misses);
}

/* Use the same update/invalidation primitives as the benchmark without its
 * IPv4-specific do_update() wrapper. Fully clear on an unknown PDU or failure.
 */
static int apply_update(CachedValidator *v, void *record, int add)
{
    struct lrtr_ip_addr updated = {0};
    uint8_t length = 0;
    int selective = updated_prefix_from_record(record, &updated, &length);
    int rc = add ? v->original.rov_pfx_add(v->original.ht, record)
                 : v->original.rov_pfx_rm(v->original.ht, record);
    if (rc != SUCCESS || !selective) {
        clear_all(&v->cache);
    } else if (v->cache.use_index) {
        selectively_clear_index(&v->cache, &updated, length);
    } else {
        selectively_clear(&v->cache, &updated, length);
    }
    return rc;
}

/* Check that exactly the expected prefixes were removed and all unaffected
 * entries remain cached, regardless of their authorization states. */
static void check_invalidation(CachedValidator *v, const char *stage,
                               const int affected[NUM_CASES], size_t count)
{
    char message[160];
    snprintf(message, sizeof(message), "%s: exact remaining cache count", stage);
    assertion(v->cache.count == NUM_CASES - count, message);
    for (size_t i = 0; i < NUM_CASES; ++i) {
        snprintf(message, sizeof(message), "%s: %s %s", stage, cases[i].name,
                 affected[i] ? "invalidated" : "preserved");
        assertion(key_present(&v->cache, &cases[i]) == !affected[i], message);
    }
    printf("After %-19s affected=%zu retained=%zu\n",
           stage, count, v->cache.count);
}

int main(int argc, char **argv)
{
    if (argc != 2 || strlen(argv[1]) != 1 ||
        (argv[1][0] != 'C' && argv[1][0] != 'D' && argv[1][0] != 'E')) {
        fprintf(stderr, "Usage: %s C|D|E\n", argv[0]);
        return 2;
    }
    const char mode = argv[1][0];
    CachedValidator *v = calloc(1, sizeof(*v));
    if (!v) { perror("validator allocate"); return 1; }
    v->original = hrov_nlbs_binary;
    v->original.wide_threshold = 5;
    v->cache.capacity = 64;
    v->cache.use_index = mode != 'C';
    v->cache.use_node_pool = mode == 'E';
    v->cache.pool = calloc(v->cache.capacity, sizeof(*v->cache.pool));
    if (v->cache.use_index)
        v->cache.worklist = calloc(v->cache.capacity, sizeof(*v->cache.worklist));
    if (!v->cache.pool || (v->cache.use_index && !v->cache.worklist)) {
        perror("cache allocate");
        return 1;
    }
    v->original.rov_init(&v->original);
    if (!v->original.ht) { fputs("h2ROV init failed\n", stderr); return 1; }
    for (size_t i = 0; i < NUM_CASES; ++i)
        lrtr_ip_str_to_addr(cases[i].address, &cases[i].addr);

    struct pdu_ipv6 parent = {0}, child = {0};
    struct pdu_ipv4 ipv4 = {0};
    char parent_text[] = "2001:db8:100::";
    char child_text[] = "2001:db8:100:1::";
    char ipv4_text[] = "198.51.100.0";
    init_pdu_v6(&parent, TROA_IPV6, parent_text, 48, 64, 65001);
    init_pdu_v6(&child, TROA_IPV6, child_text, 64, 64, 65003);
    init_pdu_v4(&ipv4, TROA_IPV4, ipv4_text, 24, 24, 65077);

    assertion(apply_update(v, &ipv4, 1) == SUCCESS, "add unrelated IPv4 ROA");
    const enum pfxv_state initial[NUM_CASES] = {N,N,N,N,N,N,V,N,N,N,N};
    check_stage(v, "before IPv6 ROAs", initial);

    const int parent_affected[NUM_CASES] = {1,1,1,1,1,0,0,1,1,0,0};
    const int child_affected[NUM_CASES] = {0,1,1,1,0,0,0,1,1,0,0};

    unsigned long old_invalidations = v->cache.selectively_invalidated;
    assertion(apply_update(v, &parent, 1) == SUCCESS, "add /48 IPv6 parent ROA");
    assertion(v->cache.selectively_invalidated - old_invalidations == 7,
              "parent /48 add invalidated seven covered route keys");
    check_invalidation(v, "add parent /48", parent_affected, 7);
    const enum pfxv_state with_parent[NUM_CASES] = {V,V,I,I,V,N,V,I,I,N,N};
    check_stage(v, "parent present", with_parent);

    old_invalidations = v->cache.selectively_invalidated;
    assertion(apply_update(v, &child, 1) == SUCCESS, "add overlapping /64 IPv6 child");
    assertion(v->cache.selectively_invalidated - old_invalidations == 5,
              "child /64 add invalidated five covered route keys");
    check_invalidation(v, "add child /64", child_affected, 5);
    const enum pfxv_state with_both[NUM_CASES] = {V,V,V,I,V,N,V,I,I,N,N};
    check_stage(v, "parent and child", with_both);

    old_invalidations = v->cache.selectively_invalidated;
    assertion(apply_update(v, &parent, 0) == SUCCESS, "withdraw IPv6 parent /48");
    assertion(v->cache.selectively_invalidated - old_invalidations == 7,
              "parent /48 withdrawal invalidated seven covered route keys");
    check_invalidation(v, "withdraw parent", parent_affected, 7);
    const enum pfxv_state child_only[NUM_CASES] = {N,I,V,I,N,N,V,I,I,N,N};
    check_stage(v, "child only", child_only);

    old_invalidations = v->cache.selectively_invalidated;
    assertion(apply_update(v, &child, 0) == SUCCESS, "withdraw IPv6 child /64");
    assertion(v->cache.selectively_invalidated - old_invalidations == 5,
              "child /64 withdrawal invalidated five covered route keys");
    check_invalidation(v, "withdraw child", child_affected, 5);
    check_stage(v, "after all v6 removal", initial);

    /* Even after many IPv6 updates, both an IPv4 Valid and IPv4 NotFound
     * cache entry must still be present (AFI separation). */
    assertion(key_present(&v->cache, &cases[6]), "unrelated IPv4 Valid retained");
    assertion(key_present(&v->cache, &cases[9]), "unrelated IPv4 NotFound retained");

    clear_all(&v->cache);
    assertion(v->cache.count == 0, "all cache entries cleared");
    assertion(v->cache.index_nodes == 0, "all trie nodes released from active index");
    free_recycled_nodes(&v->cache);
    assertion(v->cache.node_freelist_count == 0, "node pool freed on cleanup");
    free(v->cache.pool);
    free(v->cache.worklist);
    /* No h2ROV shutdown; upstream baseline does not support complete teardown. */
    printf("IPv6 cached %c regression: %u/%u checks passed\n",
           mode, checks - failures, checks);
    return failures ? 1 : 0;
}
