#include <sodium.h>
#include "ed25519_cosi.h"

/*
 * Commit to signature process
 *
 * @param mut R: public commitment to be sent to Leader [crypto_scalarmult_BYTES]
 * @param mut r: private nonce to be kept for signature generation later [crypto_core_ed25519_SCALARBYTES]
 * @returns void
 */
void ed25519_cosi_commit(unsigned char *R, unsigned char *r) {
    crypto_core_ed25519_scalar_random(r);
    crypto_scalarmult_base(R, r);
}


