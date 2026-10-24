#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "src/hrov_header.h"

/*
 * Standalone correctness test for original h2ROV.
 *
 * Authorization:
 *   192.0.2.0/24 -> AS65001, maxLength 24
 *
 * No RTR connection or Mininet topology required.
 */

static const char *state_name(enum pfxv_state state)
{
    switch (state) {
        case BGP_PFXV_STATE_VALID:
            return "VALID";

        case BGP_PFXV_STATE_INVALID:
            return "INVALID";

        case BGP_PFXV_STATE_NOT_FOUND:
            return "NOTFOUND";

        default:
            return "UNKNOWN";
    }
}

static int check_route(
    struct rov_algo_t *algo,
    const char *prefix_string,
    uint8_t prefix_len,
    uint32_t asn,
    enum pfxv_state expected
)
{
    struct lrtr_ip_addr prefix;
    enum pfxv_state result = BGP_PFXV_STATE_NOT_FOUND;

    /* Convert the IPv4 address using RTRlib. */
    lrtr_ip_str_to_addr(prefix_string, &prefix);

    int rc = algo->rov_pfx_validate(
        algo->ht,
        asn,
        &prefix,
        prefix_len,
        &result
    );

    printf(
        "Prefix: %-18s ASN: %-7u Result: %-9s "
        "Expected: %-9s %s (rc=%d)\n",
        prefix_string,
        asn,
        state_name(result),
        state_name(expected),
        result == expected ? "PASS" : "FAIL",
        rc
    );

    return result == expected;
}

int main(void)
{
    printf("\n");
    printf("========================================\n");
    printf(" h2ROV Original Validation Test\n");
    printf("========================================\n\n");

    /*
     * Copy the repository's original h2ROV
     * algorithm configuration.
     */
    struct rov_algo_t algo = hrov_nlbs_binary;

    /*
     * Select a positive wide-prefix threshold.
     * We will verify this configuration against
     * the repository's initialization semantics.
     */
    algo.wide_threshold = 5;

    /* Initialize h2ROV data structures. */
    algo.rov_init(&algo);

    if (algo.ht == NULL) {
        fprintf(stderr, "h2ROV initialization failed\n");
        return EXIT_FAILURE;
    }

    printf("[1] h2ROV initialized\n\n");

    /*
     * Create one synthetic IPv4 authorization.
     */
    struct pdu_ipv4 roa = {0};

    char authorized_prefix[] = "192.0.2.0";

    init_pdu_v4(
        &roa,
        TROA_IPV4,
        authorized_prefix,
        24,
        24,
        65001
    );

    printf("[2] Adding authorization\n");

    int add_rc = algo.rov_pfx_add(algo.ht, &roa);

    printf("    Add returned: %d\n\n", add_rc);

    /*
     * Test origin-validation correctness.
     */
    printf("[3] Running validation tests\n\n");

    int passed = 0;
    int total = 0;

    total++;
    passed += check_route(
        &algo,
        "192.0.2.0",
        24,
        65001,
        BGP_PFXV_STATE_VALID
    );

    total++;
    passed += check_route(
        &algo,
        "192.0.2.0",
        24,
        65003,
        BGP_PFXV_STATE_INVALID
    );

    total++;
    passed += check_route(
        &algo,
        "198.51.100.0",
        24,
        65004,
        BGP_PFXV_STATE_NOT_FOUND
    );

    /*
     * Withdraw the original authorization.
     */
    printf("\n[4] Withdrawing authorization\n");

    int remove_rc = algo.rov_pfx_rm(algo.ht, &roa);

    printf("    Remove returned: %d\n\n", remove_rc);

    /*
     * The route should now be NotFound,
     * assuming no other covering authorization.
     */
    printf("[5] Validation after withdrawal\n\n");

    total++;
    passed += check_route(
        &algo,
        "192.0.2.0",
        24,
        65001,
        BGP_PFXV_STATE_NOT_FOUND
    );

    printf("\n========================================\n");
    printf("Tests passed: %d/%d\n", passed, total);
    printf("========================================\n");

    /*
     * The upstream nLBS release function has
     * cleanup operations commented out.
     * Do not rely on it for memory-leak testing.
     * The OS reclaims memory at process exit.
     */

    return passed == total ? EXIT_SUCCESS : EXIT_FAILURE;
}
