#include <stdio.h>
#include "ed25519_cosi.h"
#include <sodium.h>
#include <string.h>

unsigned const char ed25519_cosi_SC_ONE[] = {
    1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};

/* ==================== *
 * SIGNATURE GENERATION *
 * ==================== */

void ed25519_cosi_commit(unsigned char *R, unsigned char *r) {
    // create secret key
    unsigned char *sk = malloc(crypto_sign_SECRETKEYBYTES);
    randombytes_buf(sk, crypto_sign_SECRETKEYBYTES);

    // create scalar and point
    crypto_core_ed25519_scalar_reduce(r, sk);
    crypto_scalarmult_ed25519_base_noclamp(R, r);

    // free memory
    free(sk);
}

void ed25519_cosi_update_public_key(unsigned char *A_sum, unsigned const char *A) {
    crypto_core_ed25519_add(A_sum, A_sum, A);
}

void ed25519_cosi_update_commit(unsigned char *R_sum, unsigned const char *R) {
    ed25519_cosi_update_public_key(R_sum, R);
}

void ed25519_cosi_challenge(
    unsigned char *c,
    unsigned const char *R,
    unsigned const char *A,
    unsigned const char *M,
    size_t m_len
) {
    unsigned char hash[crypto_hash_sha256_BYTES];

    // allocate memory
    size_t bytes_len = ed25519_cosi_COMMITBYTES + crypto_sign_PUBLICKEYBYTES + m_len;
    unsigned char *bytes = malloc(bytes_len);

    // concatenate data
    memcpy(bytes, R, ed25519_cosi_COMMITBYTES);
    memcpy(bytes + ed25519_cosi_COMMITBYTES, A, crypto_sign_PUBLICKEYBYTES);
    memcpy(bytes + ed25519_cosi_COMMITBYTES + crypto_sign_PUBLICKEYBYTES, M, m_len);

    // hash data
    crypto_hash_sha512(hash, bytes, bytes_len);

    // mod L
    crypto_core_ed25519_scalar_reduce(c, hash);

    // free memory
    free(bytes);
}

void ed25519_cosi_expand_secret(unsigned char *h, unsigned const char *a) {
    // hash
    unsigned char *digest = malloc(crypto_hash_sha512_BYTES);
    crypto_hash_sha512(digest, a, crypto_scalarmult_BYTES);

    // align bits
    memcpy(h, digest, crypto_scalarmult_BYTES);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;

    // free memory
    free(digest);
}

void ed25519_cosi_response(
    unsigned char *s,
    unsigned const char *c,
    unsigned const char *a,
    unsigned const char *r
) {
    // expand secret
    unsigned char *h = malloc(crypto_scalarmult_BYTES);
    ed25519_cosi_expand_secret(h, a);

    // (r + c * a) mod L
    crypto_core_ed25519_scalar_mul(s, c, h);
    crypto_core_ed25519_scalar_add(s, s, r);

    // free memory
    free(h);
}

void ed25519_cosi_update_response(unsigned char *s_sum, unsigned const char *s) {
    crypto_core_ed25519_scalar_mul(s_sum, s_sum, ed25519_cosi_SC_ONE);
    crypto_core_ed25519_scalar_add(s_sum, s_sum, s);
}

void ed25519_cosi_mask_init(unsigned char *Z, size_t z_len) {
    memset(Z, 255, z_len);
}

void ed25519_cosi_mask_enable(unsigned char *Z, uint32_t which) {
    Z[ed25519_cosi_mask_byte(which)] &= ~ed25519_cosi_mask_bit(which);
}

void ed25519_cosi_mask_disable(unsigned char *Z, uint32_t which) {
    Z[ed25519_cosi_mask_byte(which)] |= ed25519_cosi_mask_bit(which);
}

void ed25519_cosi_signature(
    unsigned char *S,
    unsigned const char *R,
    unsigned const char *s_sum,
    unsigned const char *Z,
    size_t z_len
) {
    // concatenate data
    memcpy(S, R, ed25519_cosi_COMMITBYTES);
    memcpy(S + ed25519_cosi_COMMITBYTES, s_sum, ed25519_cosi_RESPONSEBYTES);
    memcpy(S + ed25519_cosi_COMMITBYTES + ed25519_cosi_RESPONSEBYTES, Z, z_len);
}

/* ====================== *
 * SIGNATURE VERIFICATION *
 * ====================== */

bool ed25519_cosi_valid_signature_len(size_t len, uint32_t n) {
    return (ed25519_cosi_SIGBYTES + ed25519_cosi_mask_len(n)) == len;
}

bool ed25519_cosi_did_sign(unsigned const char *S, uint32_t which) {
    return ~S[ed25519_cosi_SIGBYTES + ed25519_cosi_mask_byte(which)] &
        ed25519_cosi_mask_bit(which);
}

uint32_t ed25519_cosi_num_signatures(unsigned const char *S, uint32_t n) {
    // @TODO: There's probably a more efficient way to do this with bitmasks...
    uint32_t result = 0;
    uint32_t i = 0;
    while (i < n) {
        if (ed25519_cosi_did_sign(S, i)) {
            result++;
        }
        i++;
    }
    return result;
}
