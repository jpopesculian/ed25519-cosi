#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include <check.h>
#include "ed25519_cosi.h"

// message
unsigned const char message[] = {0, 1, 2, 3, 4, 5};
const size_t m_len = 6;

// test key pair 1
unsigned const char pk1[] = {29, 79, 210, 207, 9, 227, 16, 185, 127, 54, 203, 220, 206, 26, 193, 31, 9, 45, 252, 131, 218, 148, 57, 4, 74, 5, 200, 63, 55, 242, 157, 157};
unsigned const char sk1[] = {72, 135, 232, 96, 132, 97, 196, 213, 199, 247, 191, 175, 93, 160, 12, 96, 174, 94, 246, 20, 215, 10, 187, 14, 221, 43, 213, 104, 66, 90, 40, 48, 29, 79, 210, 207, 9, 227, 16, 185, 127, 54, 203, 220, 206, 26, 193, 31, 9, 45, 252, 131, 218, 148, 57, 4, 74, 5, 200, 63, 55, 242, 157, 157};

// test key pair 2
unsigned const char pk2[] = {132, 238, 113, 249, 153, 177, 241, 241, 33, 88, 68, 157, 48, 53, 189, 81, 218, 127, 103, 158, 43, 26, 35, 225, 159, 73, 96, 91, 3, 120, 81, 11};
unsigned const char sk2[] = {54, 147, 9, 101, 220, 132, 212, 109, 227, 5, 144, 238, 207, 20, 228, 178, 0, 150, 254, 113, 141, 198, 2, 207, 112, 50, 175, 211, 121, 183, 72, 38, 132, 238, 113, 249, 153, 177, 241, 241, 33, 88, 68, 157, 48, 53, 189, 81, 218, 127, 103, 158, 43, 26, 35, 225, 159, 73, 96, 91, 3, 120, 81, 11};

// test key pair 3
unsigned const char pk3[] = {253, 137, 235, 90, 142, 167, 201, 25, 193, 27, 252, 129, 43, 68, 249, 225, 38, 27, 116, 23, 1, 222, 196, 49, 198, 111, 125, 117, 135, 196, 145, 250};
unsigned const char sk3[] = {19, 117, 36, 235, 68, 39, 94, 150, 197, 113, 95, 145, 225, 66, 26, 90, 45, 76, 87, 24, 80, 25, 177, 67, 105, 190, 241, 51, 122, 52, 41, 238, 253, 137, 235, 90, 142, 167, 201, 25, 193, 27, 252, 129, 43, 68, 249, 225, 38, 27, 116, 23, 1, 222, 196, 49, 198, 111, 125, 117, 135, 196, 145, 250};

// aggregate public key
unsigned const char pk[] = {20, 66, 142, 18, 3, 173, 178, 25, 160, 5, 96, 233, 250, 176, 141, 187, 16, 21, 132, 65, 161, 75, 184, 213, 138, 241, 3, 137, 247, 197, 101, 94};

// nonce 1
unsigned const char r1[] = {254, 69, 102, 175, 20, 169, 50, 183, 225, 19, 111, 165, 203, 215, 238, 201, 117, 153, 244, 209, 212, 53, 228, 74, 142, 89, 35, 101, 27, 196, 186, 8};
unsigned const char commit1[] = {86, 1, 52, 208, 127, 94, 216, 95, 22, 201, 121, 53, 75, 6, 23, 116, 203, 6, 46, 11, 139, 34, 189, 116, 6, 31, 118, 17, 241, 170, 31, 92};

// nonce 2
unsigned const char r2[] = {106, 152, 233, 186, 17, 246, 162, 111, 253, 225, 66, 152, 205, 134, 107, 67, 2, 25, 156, 179, 188, 86, 91, 190, 18, 121, 100, 49, 159, 185, 104, 9};
unsigned const char commit2[] = {77, 87, 108, 37, 120, 67, 51, 13, 162, 30, 213, 35, 27, 93, 64, 130, 184, 162, 147, 72, 126, 251, 185, 174, 198, 168, 240, 207, 15, 101, 180, 216};

// nonce 3
unsigned const char r3[] = {221, 0, 161, 118, 94, 150, 132, 108, 114, 117, 74, 17, 234, 201, 51, 1, 27, 181, 168, 251, 64, 20, 107, 149, 146, 142, 222, 191, 47, 139, 49, 12};
unsigned const char commit3[] = {233, 245, 17, 84, 240, 241, 215, 147, 250, 215, 83, 78, 16, 62, 85, 209, 225, 196, 237, 48, 81, 26, 64, 72, 85, 73, 64, 8, 35, 87, 239, 218};

// aggregate nonce
unsigned const char commit[] = {217, 13, 12, 0, 199, 125, 36, 89, 35, 69, 125, 67, 180, 199, 148, 22, 179, 112, 251, 191, 83, 216, 114, 1, 112, 228, 135, 115, 175, 28, 15, 28};

// challenge for commit with all
unsigned const char challenge[] = {125, 88, 145, 120, 145, 63, 17, 247, 209, 169, 186, 44, 247, 102, 178, 71, 16, 116, 28, 80, 5, 42, 152, 116, 53, 55, 214, 6, 196, 3, 201, 7};

// signature parts
unsigned const char s1[] = {123, 13, 126, 83, 148, 3, 106, 76, 217, 19, 123, 79, 66, 177, 20, 115, 219, 29, 221, 74, 230, 132, 17, 26, 178, 57, 80, 165, 49, 56, 216, 7};
unsigned const char s2[] = {1, 202, 80, 62, 192, 8, 132, 185, 64, 161, 212, 147, 224, 132, 170, 107, 211, 208, 28, 20, 67, 56, 31, 140, 219, 92, 141, 134, 187, 200, 210, 10};
unsigned const char s3[] = {216, 74, 248, 208, 164, 121, 226, 81, 105, 223, 46, 183, 81, 231, 2, 158, 97, 221, 62, 75, 99, 64, 110, 114, 221, 20, 18, 2, 35, 172, 188, 1};

START_TEST(ed25519_pk_sum)
{
    unsigned char A_sum[crypto_scalarmult_BYTES];
    memcpy(A_sum, pk1, crypto_scalarmult_BYTES);
    ed25519_cosi_update_public_key(A_sum, pk2);
    ed25519_cosi_update_public_key(A_sum, pk3);

    ck_assert(!sodium_compare(A_sum, pk, crypto_scalarmult_BYTES));
}
END_TEST

START_TEST(ed25519_commit_sum)
{
    unsigned char R_sum[crypto_scalarmult_BYTES];
    memcpy(R_sum, commit1, crypto_scalarmult_BYTES);
    ed25519_cosi_update_public_key(R_sum, commit2);
    ed25519_cosi_update_public_key(R_sum, commit3);

    ck_assert(!sodium_compare(R_sum, commit, crypto_scalarmult_BYTES));
}
END_TEST

START_TEST(ed25519_challenge_create)
{
    unsigned char c[crypto_scalarmult_BYTES];
    ed25519_cosi_challenge(c, commit, pk, message, m_len);

    ck_assert(!sodium_compare(c, challenge, crypto_scalarmult_BYTES));
}
END_TEST

START_TEST(ed25519_response_create)
{
    unsigned char s[crypto_scalarmult_BYTES];
    ed25519_cosi_response(s, challenge, sk1, r1);

    ck_assert(!sodium_compare(s, s1, crypto_scalarmult_BYTES));
}
END_TEST

int main(void)
{
    if (sodium_init() < 0) {
        return 1;
    }

    Suite *s1 = suite_create("Core");
    TCase *tc1_1 = tcase_create("Core");
    SRunner *sr = srunner_create(s1);
    int nf;

    suite_add_tcase(s1, tc1_1);

    tcase_add_test(tc1_1, ed25519_pk_sum);
    tcase_add_test(tc1_1, ed25519_commit_sum);
    tcase_add_test(tc1_1, ed25519_challenge_create);
    tcase_add_test(tc1_1, ed25519_response_create);

    printf("\n");
    srunner_run_all(sr, CK_ENV);
    nf = srunner_ntests_failed(sr);
    srunner_free(sr);
    printf("\n");

    return nf == 0 ? 0 : 1;
}
