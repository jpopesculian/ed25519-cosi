#include <stddef.h>

#ifndef ED25519_COSI_H
#define ED25519_COSI_H

#ifdef __cplusplus
extern "C"{
#endif

#define ed25519_cosi_NONCEBYTES 32
#define ed25519_cosi_COMMITBYTES 32
#define ed25519_cosi_RESPONSEBYTES 32
#define ed25519_cosi_CHALLENGEBYTES 32

/*
 * Length of a Collective Signature mask in bytes
 *
 * @param len: total number of participants
 */
#define ed25519_cosi_mask_len(len) ((len + 7) >> 3)

/*
 * Commit to signature process
 *
 * @param R: public commitment to be sent to Leader [ed25519_cosi_COMMITBYTES]
 * @param r: private nonce to be kept for signature generation later [ed25519_cosi_NONCEBYTES]
 * @returns void
 */
void ed25519_cosi_commit(unsigned char *R, unsigned char *r);

/*
 * Add public key to a collective public key
 *
 * @param A_sum: the sum of the public keys [crypto_sign_PUBLICKEYBYTES]
 * @param A: a singular public key to add to the sum [crypto_sign_PUBLICKEYBYTES]
 * @returns void
 */
void ed25519_cosi_update_public_key(unsigned char *A_sum, unsigned const char *A);

/*
 * Add commit message to commit sum
 *
 * @param R_sum: the sum of the commits [ed25519_cosi_COMMITBYTES]
 * @param R: a singular commit to add to the sum [ed25519_cosi_COMMITBYTES]
 * @returns void
 */
void ed25519_cosi_update_commit(unsigned char *R_sum, unsigned const char *R);

/*
 * Create cosi challenge
 *
 * @param c: output of challenge [ed25519_cosi_CHALLENGEBYTES]
 * @param R: aggregate commitments [ed25519_cosi_COMMITBYTES]
 * @param A: collective public key [crypto_sign_PUBLICKEYBYTES]
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
 * @param s: output of response [ed25519_cosi_RESPONSEBYTES]
 * @param c: generated challenge [ed25519_cosi_CHALLENGEBYTES]
 * @param a: private key of participant [crypto_sign_SECRETKEYBYTES]
 * @param r: private nonce of commitment [ed25519_cosi_NONCEBYTES]
 * @returns void
 */
void ed25519_cosi_response(
    unsigned char *s,
    unsigned const char *c,
    unsigned const char *a,
    unsigned const char *r
);

/*
 * Add signature parts to the collective signature parts
 *
 * @param s_sum: the sum of the signature parts [ed25519_cosi_RESPONSEBYTES]
 * @param s: a signature part to add to the sum [ed25519_cosi_RESPONSEBYTES]
 * @returns void
 */
void ed25519_cosi_update_response(unsigned char *s_sum, unsigned const char *s);

/*
 * Initialize a mask to all disabled
 *
 * @param Z: the mask
 * @param z_len: length of max in bytes
 * @return void
 */
void ed25519_cosi_mask_init(unsigned char *Z, size_t z_len);

/*
 * Enable a participant as a cosigner
 *
 * @param Z: the mask
 * @param which: the participant number to enable
 * @return void
 */
void ed25519_cosi_mask_enable(unsigned char *Z, size_t which);


/*
 * Disable a participant as a cosigner
 *
 * @param Z: the mask
 * @param which: the participant number to enable
 * @return void
 */
void ed25519_cosi_mask_disable(unsigned char *Z, size_t which);

/*
 * Put signature components togeter
 *
 * @param S: output of the signature [ed25519_cosi_COMMITBYTES + ed25519_cosi_RESPONSEBYTES + z_len]
 * @param R: aggregate commits [ed25519_cosi_COMMITBYTES]
 * @param s_sum: aggregate responses [ed25519_cosi_RESPONSEBYTES]
 * @param Z: signing mask
 * @param z_len: length of signing mask
 * @return void
 */
void ed25519_cosi_signature(
    unsigned char *S,
    unsigned const char *R,
    unsigned const char *s_sum,
    unsigned const char *Z,
    size_t z_len
);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_COSI_H */
