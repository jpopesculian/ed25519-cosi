# Collective Edwards-Curve Digital Signature Algorithm

Under Development and sparsely tested, please use at your own risk.

## Installation

### Dependencies

Only dependency is `libsodium` (tested with version 1.0.17)

### Build

```bash
git clone https://github.com/jpopesculian/ed25519-cosi.git $INSTALL_DIR
cd $INSTALL_DIR
make
```

### Install

To use, include the header file: `#include <ed25519_cosi.h>` and the compile
with the appropriate `LD_FLAGS` (remember to include `libsodium`). For example
if compiling, `test.c` to `myprog`

```bash
gcc -o myprog test.c $INSTALL_DIR/somelib.o -I$INSTALL_DIR -lsodium
```

## Testing

Requires [libcheck](https://libcheck.github.io/check/)

```bash
make check
```

## Usage

The Collective Edwards-Curve Digital Signature Algorithm is based upon B.
Ford's draft at
[https://tools.ietf.org/id/draft-ford-cfrg-cosi-00.html](https://tools.ietf.org/id/draft-ford-cfrg-cosi-00.html).
This library includes both creating and verifying collective signatures.

### Signature Generation

#### Setup

It's up to the implementation to decide how to communicate with participants.
The Draft suggests Protocol Buffers and has appropriate schemas. In addition an
ordered list of public keys needs to be available for the "Leader" and
a verifier to reference. In addition collective public key will be made and
distributed by using `ed25519_cosi_update_public_key` (using
`ed25519_cosi_SC_ONE` as a base value).

#### Announcement

It's up to the implementation to decide how to the Leader will announce to the
participants that a message will be signed. A collective signature mask should
be initialized here for the signature (a byte array of length
`ed25519_cosi_mask_len(n)` where `n` is the number of participants
corresponding to the public key list and should be initialized with
`ed25519_cosi_mask_init`).

#### Commitment

If a participant wants to sign he/she will create a commitment
`ed25519_cosi_commit` generating a nonce he/she must store and a public
commitment to be sent to the Leader. The Leader will then collect the public
commitments using `ed25519_cosi_update_commit` (using `ed25519_cosi_SC_ONE` as
a base value).

On commitment receipt, the Leader needs to update the collective signature mask
using `ed25519_cosi_mask_enable` for responding participants.

#### Challenge

After creating the collective commitment, the Leader will then create
a challenge with `ed25519_cosi_challenge` and broadcast the collective
challenge participants (he/she should include the message and commitment so
that the participants can verify).

#### Response

After receiving and verifying the challenge, participants will create
a response with `ed25519_cosi_response` and their stored nonce value and send
back to the Leader. On receipt of a response, the Leader will use
`ed25519_cosi_update_response` to collect the responses (using
`ed25519_cosi_SC_ZERO` as a base).

#### Signature Creation

The Leader will then combine the collective commitment, collective response and
collective signature mask together with `ed25519_cosi_signature` to create the
signature itself.

### Signature Verification

To signature can be verified in two steps. Through a policy and through cryptography.

#### Policy Verification

A policy is used to check who participated in a collective signature. It can be
such things as `m` of `n` or checking that certain people signed or any
combination / permutation of those. The library offers helpers such as
`ed25519_cosi_did_sign` and `ed25519_cosi_num_signatures` to help build such
a policy (`ed25519_cosi_valid_length` or `ed25519_cosi_valid_signature` should
be called before verifying a policy).

#### Cryptographic Verification

Given the message, signature and the list of participants public keys (in the
same order as used in the signature generation process), someone can verify the
collective signature using `ed25519_cosi_valid_signature`.
