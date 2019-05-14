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
 * Add commit message to commit sum
 *
 * @param R_sum: the sum of the commits [crypto_scalarmult_BYTES]
 * @param R: a singular commit to add to the sum [crypto_scalarmult_BYTES]
 * @returns void
 */
void ed25519_cosi_update_commits(unsigned char *R_sum, unsigned const char *R);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_COSI_H */
