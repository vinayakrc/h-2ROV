/*
 * Phase 2O: concurrent validation requests + serialized authorization changes.
 * Uses the existing benchmark cache implementation verbatim.
 *
 * IMPORTANT: A plain pthread mutex protects BOTH the mutable h2ROV table and
 * the hash/LRU/trie cache. Every reader holds it for the complete validation,
 * including cache miss and any cache insertion. Writers hold it across the
 * authorization modification, invalidation, and snapshot publication.
 * Readers are NOT parallel in this prototype. This is a correctness regression
 * for a safe coarse-grained policy, NOT a lock-free/parallel speed benchmark or
 * a live RTR/FRRouting transport test.
 *
 * Build from repository root:
 * gcc -std=gnu11 -O0 -g -I. experiments/concurrent_cache_regression.c \
 *     -L. -lhrov -lrtr -lxxhash -lm -lpthread \
 *     -o experiments/concurrent_cache_regression
 */
#define main h2rov_benchmark_main_not_used
#include "cache_profile_triepool.c"
#undef main
#include <pthread.h>
#include <inttypes.h>

#define THREADS 4
#define ROUTES 11
#define READS_PER_STAGE 64u
#define CYCLES 100u
#define STAGES 6u

typedef struct {
    const char *text;
    uint8_t len;
    uint32_t asn;
    struct lrtr_ip_addr ip;
} CheckRoute;

static CheckRoute routes[ROUTES] = {
    {"2001:db8:100::",   48,65001,{0}},
    {"2001:db8:100:1::", 64,65001,{0}},
    {"2001:db8:100:1::", 64,65003,{0}},
    {"2001:db8:100:1::", 65,65001,{0}},
    {"2001:db8:100:2::", 64,65001,{0}},
    {"2001:db8:200::",   48,65004,{0}},
    {"198.51.100.0",     24,65077,{0}},
    {"2001:db8:100:1::", 64,65099,{0}},
    {"2001:db8:100:1::",128,65001,{0}},
    {"203.0.113.0",     24,65088,{0}},
    {"2001:db8:100::",   47,65001,{0}}
};
#define N BGP_PFXV_STATE_NOT_FOUND
#define V BGP_PFXV_STATE_VALID
#define I BGP_PFXV_STATE_INVALID

/* Stage 0 snapshot #1; 1 parent withdrawn; 2 parent restored;
 * 3 snapshot #2; 4 empty snapshot; 5 original snapshot restored. */
static const enum pfxv_state expected[STAGES][ROUTES] = {
    {V,V,V,I,V,N,V,I,I,N,N},
    {N,I,V,I,N,N,V,I,I,N,N},
    {V,V,V,I,V,N,V,I,I,N,N},
    {N,N,N,N,N,V,N,N,N,V,N},
    {N,N,N,N,N,N,N,N,N,N,N},
    {V,V,V,I,V,N,V,I,I,N,N}
};
#undef N
#undef V
#undef I

typedef struct {
    CachedValidator *v;
    struct rov_algo_t snapshots[3];
    struct pdu_ipv6 parent;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    pthread_barrier_t start;
    unsigned stage;
    unsigned long stage_reads, total_reads, baseline_calls;
    unsigned long checks, failures, updates, publications;
    unsigned long long cursor;
    int finished;
} Shared;

static void test_locked(Shared *s, int ok, const char *message)
{
    ++s->checks;
    if (!ok) {
        if (++s->failures <= 20)
            fprintf(stderr, "FAIL stage=%u read=%lu: %s\n",
                    s->stage, s->total_reads, message);
    }
}

static int build_snapshot(struct rov_algo_t *next, unsigned which)
{
    *next = hrov_nlbs_binary;
    next->wide_threshold = 5;
    next->rov_init(next);
    if (!next->ht) return 0;
    struct pdu_ipv6 parent={0}, child={0}, other={0};
    struct pdu_ipv4 first={0}, second={0};
    char pfx_parent[]="2001:db8:100::";
    char pfx_child[]="2001:db8:100:1::";
    char pfx_other[]="2001:db8:200::";
    char pfx_first[]="198.51.100.0";
    char pfx_second[]="203.0.113.0";
    if (which == 0) {
        init_pdu_v6(&parent,TROA_IPV6,pfx_parent,48,64,65001);
        init_pdu_v6(&child,TROA_IPV6,pfx_child,64,64,65003);
        init_pdu_v4(&first,TROA_IPV4,pfx_first,24,24,65077);
        return next->rov_pfx_add(next->ht,&parent)==SUCCESS &&
               next->rov_pfx_add(next->ht,&child)==SUCCESS &&
               next->rov_pfx_add(next->ht,&first)==SUCCESS;
    }
    if (which == 1) {
        init_pdu_v6(&other,TROA_IPV6,pfx_other,48,48,65004);
        init_pdu_v4(&second,TROA_IPV4,pfx_second,24,24,65088);
        return next->rov_pfx_add(next->ht,&other)==SUCCESS &&
               next->rov_pfx_add(next->ht,&second)==SUCCESS;
    }
    return which == 2;
}

/* Writer and every reader hold mu across the WHOLE operation. */
static void publish_locked(Shared *s, unsigned snapshot)
{
    size_t old = s->v->cache.count;
    unsigned long before = s->v->cache.globally_invalidated;
    size_t flushed = clear_all(&s->v->cache);
    test_locked(s, flushed == old, "global flush removed all entries");
    test_locked(s, s->v->cache.globally_invalidated == before + old,
                "global invalidation counter");
    test_locked(s, s->v->cache.count == 0 &&
                s->v->cache.lru == NULL && s->v->cache.mru == NULL,
                "cache empty at snapshot publication");
    test_locked(s, s->v->cache.index_nodes == 0 &&
                s->v->cache.roots[0] == NULL &&
                s->v->cache.roots[1] == NULL,
                "prefix index empty at snapshot publication");
    s->v->original = s->snapshots[snapshot];
    ++s->publications;
}

static void selective_locked(Shared *s, int add)
{
    CachedValidator *v = s->v;
    int rc = add ? v->original.rov_pfx_add(v->original.ht, &s->parent)
                 : v->original.rov_pfx_rm(v->original.ht, &s->parent);
    test_locked(s, rc == SUCCESS, add ? "add parent ROA" : "withdraw parent ROA");
    struct lrtr_ip_addr changed={0};
    uint8_t len=0;
    int understood=updated_prefix_from_record(&s->parent,&changed,&len);
    test_locked(s, understood && len==48, "recognized changed IPv6 prefix");
    if (rc != SUCCESS || !understood) {
        clear_all(&v->cache);
    } else if (v->cache.use_index) {
        selectively_clear_index(&v->cache,&changed,len);
    } else {
        selectively_clear(&v->cache,&changed,len);
    }
    ++s->updates;
}

static void *reader(void *opaque)
{
    Shared *s = opaque;
    pthread_barrier_wait(&s->start);
    for (;;) {
        pthread_mutex_lock(&s->mu);
        if (s->finished) {
            pthread_mutex_unlock(&s->mu);
            return NULL;
        }
        unsigned stage = s->stage;
        size_t i = (size_t)(s->cursor++ % ROUTES);
        CheckRoute *r = &routes[i];
        enum pfxv_state actual = BGP_PFXV_STATE_NOT_FOUND;
        enum pfxv_state baseline = BGP_PFXV_STATE_NOT_FOUND;
        int rc1 = cached_validate(s->v,r->asn,&r->ip,r->len,&actual);
        int rc2 = s->v->original.rov_pfx_validate(s->v->original.ht,
                                                     r->asn,&r->ip,r->len,&baseline);
        ++s->baseline_calls;
        test_locked(s, rc1 == SUCCESS && rc2 == SUCCESS, "validation return codes");
        test_locked(s, actual == baseline, "cached vs authoritative h2ROV");
        test_locked(s, actual == expected[stage][i], "independent expected state");
        test_locked(s, s->v->cache.count <= s->v->cache.capacity,
                    "cache stays in capacity");
        ++s->total_reads;
        ++s->stage_reads;
        if (s->stage_reads >= READS_PER_STAGE)
            pthread_cond_signal(&s->cv);
        pthread_mutex_unlock(&s->mu);
    }
}

static void *writer(void *opaque)
{
    Shared *s = opaque;
    pthread_barrier_wait(&s->start);
    for (unsigned epoch = 0; epoch < CYCLES * STAGES; ++epoch) {
        pthread_mutex_lock(&s->mu);
        /* Wait for reader activity AFTER the preceding publication. */
        while (s->stage_reads < READS_PER_STAGE)
            pthread_cond_wait(&s->cv, &s->mu);
        unsigned next = (epoch + 1) % STAGES;
        if (next == 1) selective_locked(s, 0);
        else if (next == 2) selective_locked(s, 1);
        else if (next == 3) publish_locked(s, 1);
        else if (next == 4) publish_locked(s, 2);
        else if (next == 5) publish_locked(s, 0);
        else publish_locked(s, 0);
        s->stage = next;
        s->stage_reads = 0;
        pthread_mutex_unlock(&s->mu);
    }
    pthread_mutex_lock(&s->mu);
    s->finished = 1;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2 || strlen(argv[1]) != 1 ||
        (argv[1][0]!='C' && argv[1][0]!='D' && argv[1][0]!='E')) {
        fprintf(stderr,"Usage: %s C|D|E\n",argv[0]); return 2;
    }
    char mode = argv[1][0];
    Shared *s = calloc(1,sizeof(*s));
    CachedValidator *v = calloc(1,sizeof(*v));
    if (!s || !v) { perror("calloc"); return 1; }
    s->v = v;
    v->cache.capacity = 64;
    v->cache.use_index = mode != 'C';
    v->cache.use_node_pool = mode == 'E';
    v->cache.pool = calloc(v->cache.capacity,sizeof(*v->cache.pool));
    if (v->cache.use_index)
        v->cache.worklist = calloc(v->cache.capacity,sizeof(*v->cache.worklist));
    if (!v->cache.pool || (v->cache.use_index && !v->cache.worklist)) {
        perror("cache buffers"); return 1;
    }
    for (size_t i=0;i<ROUTES;++i)
        lrtr_ip_str_to_addr(routes[i].text,&routes[i].ip);
    for (unsigned i=0;i<3;++i)
        if (!build_snapshot(&s->snapshots[i],i)) {
            fprintf(stderr,"Could not initialize snapshot %u\n",i); return 1;
        }
    char parent[]="2001:db8:100::";
    init_pdu_v6(&s->parent,TROA_IPV6,parent,48,64,65001);
    v->original = s->snapshots[0];
    pthread_mutex_init(&s->mu,NULL);
    pthread_cond_init(&s->cv,NULL);
    pthread_barrier_init(&s->start,NULL,THREADS+1);
    pthread_t readers[THREADS], updater;
    for (unsigned i=0;i<THREADS;++i)
        if (pthread_create(&readers[i],NULL,reader,s)) {
            perror("pthread_create reader"); return 1;
        }
    if (pthread_create(&updater,NULL,writer,s)) {
        perror("pthread_create writer"); return 1;
    }
    pthread_join(updater,NULL);
    for (unsigned i=0;i<THREADS;++i)
        pthread_join(readers[i],NULL);
    pthread_mutex_lock(&s->mu);
    test_locked(s,s->total_reads >= (unsigned long)CYCLES*STAGES*READS_PER_STAGE,
                "reader activity across every update epoch");
    test_locked(s,s->publications == 4ul*CYCLES,
                "four complete table publications per cycle");
    test_locked(s,s->updates == 2ul*CYCLES,
                "two selective authorization updates per cycle");
    test_locked(s,v->cache.selectively_invalidated > 0,
                "selective invalidations exercised");
    test_locked(s,v->cache.globally_invalidated > 0,
                "global snapshot invalidations exercised");
    if (mode=='E') test_locked(s,v->cache.node_reuses>0,
                               "recycled trie nodes reused");
    clear_all(&v->cache);
    test_locked(s,v->cache.count==0 && v->cache.index_nodes==0,
                "final cache and active index empty");
    free_recycled_nodes(&v->cache);
    test_locked(s,v->cache.node_freelist_count==0,
                "final recycled-node pool empty");
    printf("Concurrent %c mutex regression: %lu/%lu checks passed; "
           "readers=%u requests=%lu selective_updates=%lu "
           "snapshot_publications=%lu hits=%lu misses=%lu trie_reuses=%zu\n",
           mode, s->checks-s->failures,s->checks,THREADS,s->total_reads,
           s->updates,s->publications,v->cache.hits,v->cache.misses,
           v->cache.node_reuses);
    unsigned long failures = s->failures;
    pthread_mutex_unlock(&s->mu);
    pthread_barrier_destroy(&s->start);
    pthread_cond_destroy(&s->cv);
    pthread_mutex_destroy(&s->mu);
    free(v->cache.pool);
    free(v->cache.worklist);
    free(v); free(s);
    /* h2ROV has no independently verified teardown API for benchmark tables;
       short-lived table allocations are intentionally left to process exit. */
    return failures ? 1 : 0;
}
