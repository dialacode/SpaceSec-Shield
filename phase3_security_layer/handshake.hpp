#pragma once

#include <openssl/evp.h>
#include <vector>

EVP_PKEY* generate_x25519_keypair();

std::vector<unsigned char> get_raw_public_key(EVP_PKEY* keypair);

EVP_PKEY* load_x25519_public_key(const std::vector<unsigned char>& raw_public_key);

std::vector<unsigned char> derive_x25519_shared_secret(
    EVP_PKEY* my_private_key,
    EVP_PKEY* peer_public_key
);

std::vector<unsigned char> hkdf_sha256_session_key(
    const std::vector<unsigned char>& shared_secret
);
