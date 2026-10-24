/*
 * IPv6 authorization/validation/withdrawal sanity checks for the upstream
 * h-2ROV nLBS implementation. No cache integration in this first test.
 * Compile from repository root with -I. -L. -lhrov -lrtr ...
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "src/hrov_header.h"

static const char *label(enum pfxv_state s)
{
    switch (s) {
        case BGP_PFXV_STATE_VALID: return "VALID";
        case BGP_PFXV_STATE_INVALID: return "INVALID";
        case BGP_PFXV_STATE_NOT_FOUND: return "NOTFOUND";
        default: return "UNKNOWN";
    }
}

static int cases = 0, passed = 0;

static void check(struct rov_algo_t *algo, const char *text,
                  uint8_t length, uint32_t asn, enum pfxv_state expected)
{
    struct lrtr_ip_addr addr;
    enum pfxv_state actual = BGP_PFXV_STATE_NOT_FOUND;
    lrtr_ip_str_to_addr(text, &addr);
    int rc = algo->rov_pfx_validate(algo->ht, asn, &addr, length, &actual);
    int ok = (rc == SUCCESS && actual == expected);
    ++cases;
    passed += ok;
    printf("%-25s /%-3u AS%-7u got=%-8s expected=%-8s %s (rc=%d)\n",
           text, length, asn, label(actual), label(expected),
           ok ? "PASS" : "FAIL", rc);
}

static int apply(struct rov_algo_t *algo, struct pdu_ipv6 *roa, int add,
                 const char *description)
{
    int rc = add ? algo->rov_pfx_add(algo->ht, roa)
                 : algo->rov_pfx_rm(algo->ht, roa);
    printf("%s: %s (rc=%d)\n", description,
           rc == SUCCESS ? "PASS" : "FAIL", rc);
    return rc == SUCCESS;
}

int main(void)
{
    struct rov_algo_t algo = hrov_nlbs_binary;
    algo.wide_threshold = 5;
    algo.rov_init(&algo);
    if (!algo.ht) {
        fprintf(stderr, "h2ROV initialization failed\n");
        return EXIT_FAILURE;
    }

    char parent_text[] = "2001:db8:100::";
    char child_text[] = "2001:db8:100:1::";
    struct pdu_ipv6 parent = {0};
    struct pdu_ipv6 child = {0};

    /* The parent ROA authorizes AS65001 through /64. */
    init_pdu_v6(&parent, TROA_IPV6, parent_text, 48, 64, 65001);
    /* A second, overlapping /64 ROA authorizes AS65003. */
    init_pdu_v6(&child, TROA_IPV6, child_text, 64, 64, 65003);

    if (!apply(&algo, &parent, 1, "Add parent /48 maxLength 64"))
        return EXIT_FAILURE;

    check(&algo, "2001:db8:100::",    48, 65001, BGP_PFXV_STATE_VALID);
    check(&algo, "2001:db8:100:1::", 64, 65001, BGP_PFXV_STATE_VALID);
    check(&algo, "2001:db8:100:1::", 64, 65003, BGP_PFXV_STATE_INVALID);
    check(&algo, "2001:db8:100:1::", 65, 65001, BGP_PFXV_STATE_INVALID);
    check(&algo, "2001:db8:200::",    48, 65004, BGP_PFXV_STATE_NOT_FOUND);

    if (!apply(&algo, &child, 1, "Add overlapping /64 AS65003"))
        return EXIT_FAILURE;
    check(&algo, "2001:db8:100:1::", 64, 65001, BGP_PFXV_STATE_VALID);
    check(&algo, "2001:db8:100:1::", 64, 65003, BGP_PFXV_STATE_VALID);

    if (!apply(&algo, &parent, 0, "Withdraw parent /48"))
        return EXIT_FAILURE;
    check(&algo, "2001:db8:100:1::", 64, 65001, BGP_PFXV_STATE_INVALID);
    check(&algo, "2001:db8:100:1::", 64, 65003, BGP_PFXV_STATE_VALID);
    check(&algo, "2001:db8:100:2::", 64, 65001, BGP_PFXV_STATE_NOT_FOUND);

    if (!apply(&algo, &child, 0, "Withdraw overlapping /64"))
        return EXIT_FAILURE;
    check(&algo, "2001:db8:100:1::", 64, 65001, BGP_PFXV_STATE_NOT_FOUND);
    check(&algo, "2001:db8:100:1::", 64, 65003, BGP_PFXV_STATE_NOT_FOUND);

    printf("IPv6 h2ROV baseline: %d/%d checks passed\n", passed, cases);
    /* Upstream nLBS release currently does not perform a full teardown. */
    return (passed == cases) ? EXIT_SUCCESS : EXIT_FAILURE;
}
