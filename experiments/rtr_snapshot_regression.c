/*
 * Single-threaded authorization-snapshot replacement regression for the
 * standalone C/D/E caches. This is NOT a live RTR transport test.
 *
 * Simulates successful construction/publication of a completely new h2ROV
 * authorization table and the mandatory global flush of validation caches.
 * It uses the same cache functions as cache_profile_triepool.c.
 *
 * Build from repository root:
 * gcc -std=gnu11 -O0 -g -I. experiments/rtr_snapshot_regression.c \
 *   -L. -lhrov -lrtr -lxxhash -lm -lpthread \
 *   -o experiments/rtr_snapshot_regression
 * Run: LD_LIBRARY_PATH="$PWD" ./experiments/rtr_snapshot_regression C|D|E
 */
#define main h2rov_benchmark_main_not_used
#include "cache_profile_triepool.c"
#undef main

typedef struct {
    const char *label;
    const char *prefix;
    uint8_t masklen;
    uint32_t asn;
    struct lrtr_ip_addr ip;
} TestRoute;

static TestRoute routes[] = {
    {"parent",        "2001:db8:100::",   48, 65001, {0}},
    {"child-65001",   "2001:db8:100:1::", 64, 65001, {0}},
    {"child-65003",   "2001:db8:100:1::", 64, 65003, {0}},
    {"beyond-maxlen", "2001:db8:100:1::", 65, 65001, {0}},
    {"sibling",       "2001:db8:100:2::", 64, 65001, {0}},
    {"other-v6",      "2001:db8:200::",   48, 65004, {0}},
    {"first-v4",      "198.51.100.0",      24, 65077, {0}},
    {"child-65099",   "2001:db8:100:1::", 64, 65099, {0}},
    {"v6-host",       "2001:db8:100:1::",128, 65001, {0}},
    {"second-v4",     "203.0.113.0",       24, 65088, {0}},
    {"broader-v6",    "2001:db8:100::",   47, 65001, {0}}
};
#define ROUTES (sizeof(routes) / sizeof(routes[0]))

static const enum pfxv_state snapshot_one[] = {
    BGP_PFXV_STATE_VALID, BGP_PFXV_STATE_VALID, BGP_PFXV_STATE_VALID,
    BGP_PFXV_STATE_INVALID, BGP_PFXV_STATE_VALID, BGP_PFXV_STATE_NOT_FOUND,
    BGP_PFXV_STATE_VALID, BGP_PFXV_STATE_INVALID, BGP_PFXV_STATE_INVALID,
    BGP_PFXV_STATE_NOT_FOUND, BGP_PFXV_STATE_NOT_FOUND
};
static const enum pfxv_state snapshot_two[] = {
    BGP_PFXV_STATE_NOT_FOUND, BGP_PFXV_STATE_NOT_FOUND,
    BGP_PFXV_STATE_NOT_FOUND, BGP_PFXV_STATE_NOT_FOUND,
    BGP_PFXV_STATE_NOT_FOUND, BGP_PFXV_STATE_VALID,
    BGP_PFXV_STATE_NOT_FOUND, BGP_PFXV_STATE_NOT_FOUND,
    BGP_PFXV_STATE_NOT_FOUND, BGP_PFXV_STATE_VALID,
    BGP_PFXV_STATE_NOT_FOUND
};

static unsigned assertions, failures;
static void verify(int ok, const char *what)
{
    ++assertions;
    if (!ok) { ++failures; fprintf(stderr, "FAIL: %s\n", what); }
}

static int present(const Cache *c, const TestRoute *r)
{
    CacheKey key = make_key(r->asn, &r->ip, r->masklen);
    for (const CacheEntry *e = c->bucket[bucket_for(&key)]; e; e=e->bucket_next)
        if (same_key(&e->key, &key)) return 1;
    return 0;
}

/* Independently call the authoritative h2ROV API and compare cache results. */
static void verify_snapshot(CachedValidator *v, const char *label,
                            const enum pfxv_state expected[ROUTES])
{
    unsigned long before_hits = v->cache.hits;
    unsigned long before_misses = v->cache.misses;
    for (size_t i=0; i<ROUTES; ++i) {
        TestRoute *r = &routes[i];
        enum pfxv_state baseline = BGP_PFXV_STATE_NOT_FOUND;
        int rc0 = v->original.rov_pfx_validate(v->original.ht, r->asn,
                                                 &r->ip, r->masklen, &baseline);
        enum pfxv_state cached = BGP_PFXV_STATE_NOT_FOUND;
        int rc1 = cached_validate(v, r->asn, &r->ip, r->masklen, &cached);
        char msg[220];
        snprintf(msg, sizeof(msg), "%s: original expected classification %s",label,r->label);
        verify(rc0 == SUCCESS && baseline == expected[i], msg);
        snprintf(msg, sizeof(msg), "%s: cached matches h2ROV %s",label,r->label);
        verify(rc1 == SUCCESS && cached == baseline, msg);
        cached = BGP_PFXV_STATE_NOT_FOUND;
        rc1 = cached_validate(v, r->asn, &r->ip, r->masklen, &cached);
        snprintf(msg, sizeof(msg), "%s: second lookup correct %s",label,r->label);
        verify(rc1 == SUCCESS && cached == baseline, msg);
        snprintf(msg, sizeof(msg), "%s: key indexed/present %s",label,r->label);
        verify(present(&v->cache,r),msg);
    }
    verify(v->cache.count == ROUTES, "all route keys populated");
    verify(v->cache.hits - before_hits == ROUTES, "second lookup is a hit for every route");
    verify(v->cache.misses - before_misses == ROUTES, "exactly one miss per route on fresh snapshot");
    verify(v->cache.count <= v->cache.capacity, "capacity respected");
    if (v->cache.use_index)
        verify(v->cache.index_nodes > 0 && v->cache.roots[0] && v->cache.roots[1],
               "both AFI prefix indices populated");
    printf("Snapshot %-18s PASS-CHECKED: count=%zu hits=%lu misses=%lu active_nodes=%zu\n",
           label, v->cache.count, v->cache.hits, v->cache.misses,
           v->cache.index_nodes);
}

/* Snapshot #1 and #4 contain overlapping IPv6 plus IPv4 authorization.
 * Snapshot #2 covers unrelated IPv6 + a different IPv4 authorization.
 * Snapshot #3 is completely empty.
 */
static int prepare_snapshot(struct rov_algo_t *next, unsigned which)
{
    *next = hrov_nlbs_binary;
    next->wide_threshold = 5;
    next->rov_init(next);
    if (!next->ht) return 0;
    struct pdu_ipv6 parent={0}, child={0}, other_v6={0};
    struct pdu_ipv4 first_v4={0}, second_v4={0};
    char parent_pfx[]="2001:db8:100::";
    char child_pfx[]="2001:db8:100:1::";
    char other_pfx[]="2001:db8:200::";
    char first_pfx[]="198.51.100.0";
    char second_pfx[]="203.0.113.0";
    if (which == 1 || which == 4) {
        init_pdu_v6(&parent,TROA_IPV6,parent_pfx,48,64,65001);
        init_pdu_v6(&child,TROA_IPV6,child_pfx,64,64,65003);
        init_pdu_v4(&first_v4,TROA_IPV4,first_pfx,24,24,65077);
        return next->rov_pfx_add(next->ht,&parent)==SUCCESS &&
               next->rov_pfx_add(next->ht,&child)==SUCCESS &&
               next->rov_pfx_add(next->ht,&first_v4)==SUCCESS;
    }
    if (which == 2) {
        init_pdu_v6(&other_v6,TROA_IPV6,other_pfx,48,48,65004);
        init_pdu_v4(&second_v4,TROA_IPV4,second_pfx,24,24,65088);
        return next->rov_pfx_add(next->ht,&other_v6)==SUCCESS &&
               next->rov_pfx_add(next->ht,&second_v4)==SUCCESS;
    }
    return which==3;
}

/* Single-threaded simulation of a successful whole-table publication.
 * Important: in production, synchronization or a generation barrier must
 * prevent lookups during this transition. This test does neither.
 */
static void publish_snapshot(CachedValidator *v, struct rov_algo_t *next,
                             unsigned which)
{
    size_t previously_cached = v->cache.count;
    unsigned long old_global = v->cache.globally_invalidated;
    unsigned long old_selective = v->cache.selectively_invalidated;
    size_t removed = clear_all(&v->cache);
    verify(removed == previously_cached, "global reset removes all cached entries");
    verify(v->cache.count==0 && !v->cache.lru && !v->cache.mru,
           "LRU empty after complete snapshot reset");
    verify(v->cache.index_nodes==0 && !v->cache.roots[0] && !v->cache.roots[1],
           "no active IPv4 or IPv6 trie nodes remain");
    verify(v->cache.globally_invalidated-old_global==previously_cached,
           "global invalidation counter updated");
    verify(v->cache.selectively_invalidated==old_selective,
           "whole-table reset does not perform selective invalidation");
    for (size_t i=0;i<ROUTES;++i)
        verify(!present(&v->cache,&routes[i]), "no stale hash entries after reset");
    v->original=*next;
    printf("Published snapshot %u: flushed %zu results, recycled trie nodes=%zu\n",
           which, removed, v->cache.node_freelist_count);
}

int main(int argc, char **argv)
{
    if (argc!=2 || strlen(argv[1])!=1 ||
        (argv[1][0]!='C' && argv[1][0]!='D' && argv[1][0]!='E')) {
        fprintf(stderr,"Usage: %s C|D|E\n",argv[0]); return 2;
    }
    char mode=argv[1][0];
    CachedValidator *v=calloc(1,sizeof(*v));
    if (!v) { perror("calloc validator"); return 1; }
    v->cache.capacity=64;
    v->cache.use_index=(mode!='C');
    v->cache.use_node_pool=(mode=='E');
    v->cache.pool=calloc(v->cache.capacity,sizeof(*v->cache.pool));
    if (v->cache.use_index)
        v->cache.worklist=calloc(v->cache.capacity,sizeof(*v->cache.worklist));
    if (!v->cache.pool || (v->cache.use_index && !v->cache.worklist)) {
        perror("cache allocation"); return 1;
    }
    for (size_t i=0;i<ROUTES;++i)
        lrtr_ip_str_to_addr(routes[i].prefix,&routes[i].ip);

    for (unsigned which=1; which<=4; ++which) {
        struct rov_algo_t next={0};
        if (!prepare_snapshot(&next,which)) {
            fprintf(stderr,"FAIL: prepare snapshot %u\n",which); return 1;
        }
        publish_snapshot(v,&next,which);
        const enum pfxv_state *expected =
            (which==1 || which==4) ? snapshot_one :
            (which==2 ? snapshot_two : NULL);
        enum pfxv_state empty[ROUTES];
        for (size_t i=0;i<ROUTES;++i) empty[i]=BGP_PFXV_STATE_NOT_FOUND;
        verify_snapshot(v, which==1 ? "initial mixed" : which==2 ? "replaced mixed" :
                        which==3 ? "empty" : "restored mixed",
                        expected ? expected : empty);
    }

    if (mode=='E')
        verify(v->cache.node_reuses>0, "E reuses pruned trie nodes across snapshot changes");
    clear_all(&v->cache);
    verify(v->cache.count==0 && v->cache.index_nodes==0,"final active cache empty");
    free_recycled_nodes(&v->cache);
    verify(v->cache.node_freelist_count==0,"free list released");
    free(v->cache.pool);
    free(v->cache.worklist);
    free(v);
    /* Upstream library does not expose a reliable full table teardown.
     * The four short-lived test table allocations are intentionally not freed.
     */
    printf("RTR-style snapshot %c regression: %u/%u checks passed\n",
           mode,assertions-failures,assertions);
    return failures ? 1 : 0;
}
