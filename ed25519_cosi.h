#include <stddef.h>

#ifndef ED25519_COSI_H
#define ED25519_COSI_H

#ifdef __cplusplus
extern "C"{
#endif

/*
 * Commit to signature process
 *
 * @param R: public commitment to be sent to Leader [crypto_scalarmult_BYTES]
 * @param r: private nonce to be kept for signature generation later [crypto_core_ed25519_SCALARBYTES]
 * @returns void
 */
void ed25519_cosi_commit(unsigned char *R, unsigned char *r);

/*
 * Add public key to a collective public key
 *
 * @param A_sum: the sum of the public keys [crypto_scalarmult_BYTES]
 * @param A: a singular public key to add to the sum [crypto_scalarmult_BYTES]
 * @returns void
 */
void ed25519_cosi_update_public_key(unsigned char *A_sum, unsigned const char *A);

/*
 * Add commit message to commit sum
 *
 * @param R_sum: the sum of the commits [crypto_scalarmult_BYTES]
 * @param R: a singular commit to add to the sum [crypto_scalarmult_BYTES]
 * @returns void
 */
void ed25519_cosi_update_commit(unsigned char *R_sum, unsigned const char *R);

/*
 * Create cosi challenge
 *
 * @param c: output of challenge [crypto_scalarmult_BYTES]
 * @param R: aggregate commitments [crypto_scalarmult_BYTES]
 * @param A: collective public key [crypto_scalarmult_BYTES]
 * @param M: message to be signed
 * @param m_len: length of message to be signed
 * @returns void
 */
void ed25519_cosi_challenge(
    unsigned char *c,
    unsigned const char *R,
    unsigned const char *A,
    unsigned const char *M,
    size_t m_len
);

/*
 * Create cosi response (signature part)
 *
 * @param s: output of response [crypto_scalarmult_BYTES]
 * @param c: generated challenge [crypto_scalarmult_BYTES]
 * @param a: private key of participant [crypto_core_ed25519_SCALARBYTES]
 * @param r: private nonce of commitment [crypto_core_ed25519_SCALARBYTES]
 * @returns void
 */
void ed25519_cosi_response(
    unsigned char *s,
    unsigned const char *c,
    unsigned const char *a,
    unsigned const char *r
);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_COSI_H */
