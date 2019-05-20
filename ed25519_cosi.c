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

unsigned const char ed25519_cosi_SC_EIGHT[] = {
    8, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};

/* ==================== *
 * SIGNATURE GENERATION *
 * ==================== */

void ed25519_cosi_commit(unsigned char *R, unsigned char *r) {
    // create secret key
    unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
    randombytes_buf(sk, crypto_sign_ed25519_SECRETKEYBYTES);

    // create scalar and point
    crypto_core_ed25519_scalar_reduce(r, sk);
    crypto_scalarmult_ed25519_base_noclamp(R, r);

    // zero out unused memory
    sodium_memzero(sk, crypto_sign_ed25519_SECRETKEYBYTES);
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
    size_t bytes_len = ed25519_cosi_COMMITBYTES + crypto_sign_ed25519_PUBLICKEYBYTES + m_len;
    unsigned char *bytes = sodium_malloc(bytes_len);

    // concatenate data
    memcpy(bytes, R, ed25519_cosi_COMMITBYTES);
    memcpy(bytes + ed25519_cosi_COMMITBYTES, A, crypto_sign_ed25519_PUBLICKEYBYTES);
    memcpy(bytes + ed25519_cosi_COMMITBYTES + crypto_sign_ed25519_PUBLICKEYBYTES, M, m_len);

    // hash data
    crypto_hash_sha512(hash, bytes, bytes_len);

    // mod L
    crypto_core_ed25519_scalar_reduce(c, hash);

    // sodium_free memory
    sodium_free(bytes);
}

void ed25519_cosi_expand_secret(unsigned char *h, unsigned const char *a) {
    // hash
    unsigned char digest[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(digest, a, crypto_scalarmult_ed25519_BYTES);

    // align bits
    memcpy(h, digest, crypto_scalarmult_ed25519_BYTES);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
}

void ed25519_cosi_response(
    unsigned char *s,
    unsigned const char *c,
    unsigned const char *a,
    unsigned const char *r
) {
    unsigned char h[crypto_scalarmult_ed25519_BYTES];
    ed25519_cosi_expand_secret(h, a);

    // (r + c * a) mod L
    crypto_core_ed25519_scalar_mul(s, c, h);
    crypto_core_ed25519_scalar_add(s, s, r);
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
    return ed25519_cosi_sig_len_for_n(n) == len;
}

bool ed25519_cosi_did_sign(unsigned const char *S, uint32_t which) {
    return ~S[ed25519_cosi_BASESIGBYTES + ed25519_cosi_mask_byte(which)] &
        ed25519_cosi_mask_bit(which);
}

uint32_t ed25519_cosi_num_signatures(unsigned const char *S, uint32_t n) {
    // @TODO: There's probably a more efficient way to do this with bitmasks
    uint32_t result = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (ed25519_cosi_did_sign(S, i)) {
            result++;
        }
    }
    return result;
}

bool ed25519_cosi_valid_signature(
    unsigned const char *M,
    size_t m_len,
    unsigned const char *A,
    get_public_key_fn get_a,
    unsigned const char *S,
    size_t s_len,
    uint32_t n
) {
    unsigned const char *R = S;
    unsigned const char *s_sum = S + ed25519_cosi_COMMITBYTES;

    unsigned char c[ed25519_cosi_CHALLENGEBYTES];
    unsigned char T[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char eight[crypto_scalarmult_ed25519_BYTES];
    unsigned char right[crypto_scalarmult_ed25519_BYTES];
    unsigned char left[crypto_scalarmult_ed25519_BYTES];

    if (!crypto_core_ed25519_is_valid_point(R)) {
        return false;
    }
    if (!ed25519_cosi_valid_signature_len(s_len, n)) {
        return false;
    }
    // TODO check if "response" is less than L
    if (sodium_is_zero(s_sum, ed25519_cosi_RESPONSEBYTES)) {
        return false;
    }

    ed25519_cosi_challenge(c, R, A, M, m_len);

    // compute inverse public key
    memcpy(T, ed25519_cosi_SC_ONE, crypto_scalarmult_ed25519_BYTES);
    for (uint32_t i = 0; i < n; i++) {
        if (!ed25519_cosi_did_sign(S, i)) {
            ed25519_cosi_update_public_key(T, get_a(i));
        }
    }
    crypto_core_ed25519_sub(T, A, T);

    memcpy(eight, ed25519_cosi_SC_ONE, crypto_scalarmult_ed25519_BYTES);
    eight[0] = 8;

    // [8][c]T
    if (crypto_scalarmult_ed25519_noclamp(T, c, T)) {
        return false;
    }
    if (crypto_scalarmult_ed25519_noclamp(T, ed25519_cosi_SC_EIGHT, T)) {
        return false;
    }

    // [8]R
    if (crypto_scalarmult_ed25519_noclamp(right, ed25519_cosi_SC_EIGHT, R)) {
        return false;
    };

    // [8]R + [8][c]T
    crypto_core_ed25519_add(right, right, T);

    // [8][s]B
    crypto_scalarmult_ed25519_base_noclamp(left, s_sum);
    if (crypto_scalarmult_ed25519_noclamp(left, ed25519_cosi_SC_EIGHT, left)) {
        return false;
    };

    return !sodium_memcmp(left, right, crypto_scalarmult_ed25519_BYTES);
}
