#include <sodium.h>
#include "ed25519_cosi.h"

void ed25519_cosi_commit(unsigned char *R, unsigned char *r) {
    crypto_core_ed25519_scalar_random(r);
    crypto_scalarmult_base(R, r);
}

void ed25519_cosi_update_commits(unsigned char *R_sum, unsigned const char *R) {
    sodium_add(R_sum, R, crypto_scalarmult_BYTES);
}


void ed25519_cosi_challenge(unsigned char *c, unsigned const char *R_sum) {}
