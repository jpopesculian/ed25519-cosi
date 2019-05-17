#include <stdio.h>
#include "ed25519_cosi.h"
#include <sodium.h>
#include <string.h>

unsigned const char ED25519_COSI_SC_ONE[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void ed25519_cosi_commit(unsigned char *R, unsigned char *r) {
    randombytes_buf(r, crypto_core_ed25519_SCALARBYTES);
    crypto_scalarmult_ed25519_base(R, r);
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
    size_t bytes_len = 2 * crypto_scalarmult_BYTES + m_len;
    unsigned char *bytes = malloc(bytes_len);

    // concatenate data
    memcpy(bytes, R, crypto_scalarmult_BYTES);
    memcpy(bytes + crypto_scalarmult_BYTES, A, crypto_scalarmult_BYTES);
    memcpy(bytes + 2 * crypto_scalarmult_BYTES, M, m_len);

    // hash data
    crypto_hash_sha512(hash, bytes, bytes_len);

    // mod L
    crypto_core_ed25519_scalar_reduce(c, hash);

    // free memory
    free(bytes);
}

void ed25519_cosi_expand_secret(unsigned char *h, unsigned const char *a) {
    unsigned char digest[64];
    crypto_hash_sha512(digest, a, crypto_scalarmult_BYTES);
    memcpy(h, digest, crypto_scalarmult_BYTES);
    h[0] = h[0] & 248;
    h[31] = h[31] & 63;
    h[31] = h[31] | 64;
}

void ed25519_cosi_response(
    unsigned char *s,
    unsigned const char *c,
    unsigned const char *a,
    unsigned const char *r
) {
    // expand secret
    unsigned char h[crypto_scalarmult_BYTES];
    ed25519_cosi_expand_secret(h, a);

    // (r + c * a) mod L
    crypto_core_ed25519_scalar_mul(s, c, h);
    crypto_core_ed25519_scalar_add(s, s, r);
}

void ed25519_cosi_update_response(unsigned char *s_sum, unsigned const char *s) {
    crypto_core_ed25519_scalar_mul(s_sum, s_sum, ED25519_COSI_SC_ONE);
    crypto_core_ed25519_scalar_add(s_sum, s_sum, s);
}

void ed25519_cosi_mask_init(unsigned char *Z, size_t z_len) {
    memset(Z, 255, z_len);
}

void ed25519_cosi_mask_enable(unsigned char *Z, size_t which) {
    size_t byte = which >> 3;
    size_t bit = 1 << (which & 7);
    Z[byte] = Z[byte] & ~bit;
}

void ed25519_cosi_mask_disable(unsigned char *Z, size_t which) {
    size_t byte = which >> 3;
    size_t bit = 1 << (which & 7);
    Z[byte] = Z[byte] | bit;
}

void ed25519_cosi_signature(
    unsigned char *S,
    unsigned const char *R,
    unsigned const char *s_sum,
    unsigned const char *Z,
    size_t z_len
) {
    // concatenate data
    memcpy(S, R, crypto_scalarmult_BYTES);
    memcpy(S + crypto_scalarmult_BYTES, s_sum, crypto_scalarmult_BYTES);
    memcpy(S + 2 * crypto_scalarmult_BYTES, Z, z_len);
}
