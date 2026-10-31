#!/usr/bin/env python3
"""Create Configuration F from an existing h2ROV VRP-mix benchmark.

Run from the repository root. F is experimental: window-based controller,
no ML, no production FRR/RTR integration. Original file is left unchanged.
"""
from pathlib import Path
import re

src = Path('experiments/cache_profile_vrpmix.c')
dst = Path('experiments/cache_profile_adaptive.c')
if not src.is_file():
    raise SystemExit(f'Missing source: {src}. Run from the h-2ROV repository root.')
if dst.exists():
    raise SystemExit(f'{dst} already exists; refusing to overwrite it.')
s = src.read_text()

def replace_once(old, new, what):
    global s
    count = s.count(old)
    if count != 1:
        raise SystemExit(f'Expected exactly one {what}, found {count}; no file created.')
    s = s.replace(old, new, 1)

replace_once("argv[1][0] > 'E'", "argv[1][0] > 'F'", 'mode upper bound')
replace_once('Usage: %s A|B|C|D|E', 'Usage: %s A|B|C|D|E|F', 'usage modes')
replace_once("v.cache.use_index = mode == 'D' || mode == 'E';",
             "v.cache.use_index = mode == 'D' || mode == 'E' || mode == 'F';",
             'index-mode initialization')
replace_once('if (do_update(&v, &roa, mode, 1) != SUCCESS)',
             "if (do_update(&v, &roa, mode == 'F' ? 'D' : mode, 1) != SUCCESS)",
             'initial authorization insertion')
replace_once('if (do_update(&v, &roa, mode, add) != SUCCESS)',
             "if (do_update(&v, &roa, mode == 'F' ? 'D' : mode, add) != SUCCESS)",
             'timed authorization update')

replace_once('    size_t num_routes = argc > 6 ? (size_t)strtoull(argv[6], NULL, 10) : DEFAULT_NUM_ROUTES;',
'''    size_t num_routes = argc > 6 ? (size_t)strtoull(argv[6], NULL, 10) : DEFAULT_NUM_ROUTES;
    const char *profile = argc > 7 ? argv[7] : "uniform";
    if (strcmp(profile, "uniform") && strcmp(profile, "phase") &&
        strcmp(profile, "reverse")) {
        fprintf(stderr, "Profile must be uniform, phase, or reverse\\n");
        return 2;
    }''', 'profile argument')
replace_once('route_count 32..65536]\\n',
             'route_count 32..65536] [uniform|phase|reverse]\\n', 'usage profile')
replace_once('''    for (size_t i = 0; i < requests; ++i)
        indices[i] = next_random(&rand_state) % num_routes;''',
'''    /* Phase workload: first half uniform over all routes, then 64 hot keys.
     * Reverse workload: first half hot, then uniform. Same trace for A..F.
     * All requests and expected results retain the original workload semantics. */
    for (size_t i = 0; i < requests; ++i) {
        uint32_t index = next_random(&rand_state) % num_routes;
        const int hot = (strcmp(profile, "phase") == 0 && i >= requests / 2) ||
                        (strcmp(profile, "reverse") == 0 && i < requests / 2);
        if (hot && num_routes > 64u) index %= 64u;
        indices[i] = index;
    }''', 'workload generator')

controller = r'''
/* Configuration F — experimental workload-aware controller.
 * Each decision window has 10,000 requests. Only aggregate counts are read;
 * the per-validation path is either original h2ROV or existing indexed cache.
 * It is intentionally single-threaded, like the existing benchmark.
 */
#define ADAPT_WINDOW 10000u
#define ADAPT_DIRECT_WINDOWS 10u
#define ADAPT_PROBE_WINDOWS 3u

typedef enum { ADAPT_DIRECT, ADAPT_CACHE, ADAPT_PROBE } AdaptiveMode;
typedef struct {
    AdaptiveMode mode;
    unsigned long window_requests, direct_windows, probe_windows;
    unsigned long switches, probes, direct_requests, cached_requests;
    unsigned long previous_hits, previous_misses, previous_evictions;
} AdaptiveController;

static const char *adaptive_mode_name(AdaptiveMode mode)
{
    return mode == ADAPT_DIRECT ? "DIRECT" :
           mode == ADAPT_CACHE ? "CACHE" : "PROBE";
}

static void adaptive_baseline(AdaptiveController *a, const Cache *c)
{
    a->previous_hits = c->hits;
    a->previous_misses = c->misses;
    a->previous_evictions = c->evictions;
}

static void adaptive_set_mode(CachedValidator *v, AdaptiveController *a,
                              AdaptiveMode next)
{
    if (a->mode == next) return;
    /* Flush on bypass and before probing; no stale entries can survive a
     * direct-only interval. Known ROA updates still use indexed invalidation
     * when the cache is enabled; unknown/reset updates use the base fallback. */
    if (next == ADAPT_DIRECT || next == ADAPT_PROBE)
        clear_all(&v->cache);
    a->mode = next;
    ++a->switches;
    a->direct_windows = 0;
    a->probe_windows = 0;
    a->window_requests = 0;
    if (next == ADAPT_PROBE) ++a->probes;
    adaptive_baseline(a, &v->cache);
}

static int adaptive_validate(CachedValidator *v, AdaptiveController *a,
                             uint32_t asn, const struct lrtr_ip_addr *prefix,
                             uint8_t masklen, enum pfxv_state *state)
{
    if (a->mode == ADAPT_DIRECT) {
        ++a->direct_requests;
        return v->original.rov_pfx_validate(v->original.ht, asn,
                                             prefix, masklen, state);
    }
    ++a->cached_requests;
    return cached_validate(v, asn, prefix, masklen, state);
}

static void adaptive_observe(CachedValidator *v, AdaptiveController *a)
{
    if (++a->window_requests < ADAPT_WINDOW) return;
    a->window_requests = 0;
    if (a->mode == ADAPT_DIRECT) {
        if (++a->direct_windows >= ADAPT_DIRECT_WINDOWS)
            adaptive_set_mode(v, a, ADAPT_PROBE);
        return;
    }

    const Cache *c = &v->cache;
    unsigned long h = c->hits - a->previous_hits;
    unsigned long m = c->misses - a->previous_misses;
    unsigned long e = c->evictions - a->previous_evictions;
    const double hit_rate = (h + m) ? (double)h / (double)(h + m) : 0.0;
    const double eviction_fraction = m ? (double)e / (double)m : 0.0;
    adaptive_baseline(a, c);

    if (a->mode == ADAPT_PROBE) {
        /* Reject clear thrashing quickly, but allow a large cache to warm up
         * before judging an initially low hit rate. */
        if (hit_rate < 0.05 && eviction_fraction > 0.80) {
            adaptive_set_mode(v, a, ADAPT_DIRECT);
        } else if (++a->probe_windows >= ADAPT_PROBE_WINDOWS) {
            if (hit_rate >= 0.50 && eviction_fraction <= 0.50)
                adaptive_set_mode(v, a, ADAPT_CACHE);
            else
                adaptive_set_mode(v, a, ADAPT_DIRECT);
        }
    } else if (hit_rate < 0.15 && eviction_fraction > 0.50) {
        adaptive_set_mode(v, a, ADAPT_DIRECT);
    }
}

'''
replace_once('int main(int argc, char **argv)', controller + 'int main(int argc, char **argv)',
             'main function insertion')
replace_once('    int present = 1;\n',
'''    AdaptiveController adaptive = {0};
    adaptive.mode = ADAPT_PROBE;
    adaptive.probes = 1;
    adaptive_baseline(&adaptive, &v.cache);
    int present = 1;
''', 'adaptive controller initialization')

old_validation = '''        if (mode == 'A') {
            rc = v.original.rov_pfx_validate(v.original.ht, r->asn,
                                             &r->addr, r->len, &state);
        } else {
            rc = cached_validate(&v, r->asn, &r->addr, r->len, &state);
        }'''
new_validation = '''        if (mode == 'A') {
            rc = v.original.rov_pfx_validate(v.original.ht, r->asn,
                                             &r->addr, r->len, &state);
        } else if (mode == 'F') {
            rc = adaptive_validate(&v, &adaptive, r->asn, &r->addr, r->len, &state);
        } else {
            rc = cached_validate(&v, r->asn, &r->addr, r->len, &state);
        }'''
replace_once(old_validation, new_validation, 'validation mode dispatch')
replace_once('        digest = digest_step(digest, state, i);',
'''        digest = digest_step(digest, state, i);
        if (mode == 'F') adaptive_observe(&v, &adaptive);''',
             'adaptive window observation')
replace_once('''           static_vrps);
    free(indices);''',
'''           static_vrps);
    if (mode == 'F') {
        fprintf(stderr,
                "ADAPTIVE profile=%s final=%s switches=%lu probes=%lu "
                "direct_requests=%lu cached_requests=%lu\\n",
                profile, adaptive_mode_name(adaptive.mode),
                adaptive.switches, adaptive.probes,
                adaptive.direct_requests, adaptive.cached_requests);
    }
    free(indices);''', 'adaptive performance summary')

# No edits are made to the original A..E source. The output is deliberately
# separate to avoid changing known baselines; run all modes from this file
# to compare phase/reverse workloads fairly.
dst.write_text(s)
print(f'Created {dst} ({len(s.splitlines())} lines)')
print('Next: gcc -std=gnu11 -O2 -I. experiments/cache_profile_adaptive.c '
      '-L. -lhrov -lrtr -lxxhash -lm -lpthread -o experiments/cache_profile_adaptive')
