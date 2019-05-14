#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include <check.h>
#include "ed25519_cosi.h"

START_TEST(ed25519_cosi_commit_sum)
{
    unsigned const char first[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    unsigned const char second[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    unsigned const char third[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3};
    unsigned const char sum[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6};

    unsigned char R_sum[crypto_scalarmult_BYTES];
    memset(R_sum, 0, crypto_scalarmult_BYTES);
    ed25519_cosi_update_commits(R_sum, first);
    ed25519_cosi_update_commits(R_sum, second);
    ed25519_cosi_update_commits(R_sum, third);

    int res = memcmp(R_sum, sum, crypto_scalarmult_BYTES);
    ck_assert_int_eq(0, res);
}
END_TEST

int main(void)
{
    Suite *s1 = suite_create("Core");
    TCase *tc1_1 = tcase_create("Core");
    SRunner *sr = srunner_create(s1);
    int nf;

    suite_add_tcase(s1, tc1_1);

    tcase_add_test(tc1_1, ed25519_cosi_commit_sum);

    srunner_run_all(sr, CK_ENV);
    nf = srunner_ntests_failed(sr);
    srunner_free(sr);

    return nf == 0 ? 0 : 1;
}
