#include "handshake.hpp"

#include <openssl/crypto.h>
#include <iostream>
#include <vector>
#include <cstdio>

void print_hex(const std::string& label, const std::vector<unsigned char>& data) {
    std::cout << label;
    for (unsigned char c : data) {
        printf("%02x", c);
    }
    std::cout << "\n";
}

bool secure_equal(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

int main() {
    std::cout << "=== SpaceSec Shield Phase 3 Secure Handshake Test ===\n";

    EVP_PKEY* ground_keypair = generate_x25519_keypair();
    EVP_PKEY* satellite_keypair = generate_x25519_keypair();

    if (!ground_keypair || !satellite_keypair) {
        std::cout << "[FAIL] Keypair generation failed.\n";
        return 1;
    }

    std::vector<unsigned char> ground_public = get_raw_public_key(ground_keypair);
    std::vector<unsigned char> satellite_public = get_raw_public_key(satellite_keypair);

    if (ground_public.size() != 32 || satellite_public.size() != 32) {
        std::cout << "[FAIL] Public key extraction failed.\n";
        return 1;
    }

    std::cout << "Ground Station public key size: " << ground_public.size() << " bytes\n";
    std::cout << "Satellite public key size: " << satellite_public.size() << " bytes\n";
    std::cout << "[PASS] Ephemeral X25519 public keys generated.\n";

    EVP_PKEY* satellite_public_loaded = load_x25519_public_key(satellite_public);
    EVP_PKEY* ground_public_loaded = load_x25519_public_key(ground_public);

    if (!satellite_public_loaded || !ground_public_loaded) {
        std::cout << "[FAIL] Public key loading failed.\n";
        return 1;
    }

    std::vector<unsigned char> ground_shared = derive_x25519_shared_secret(
        ground_keypair,
        satellite_public_loaded
    );

    std::vector<unsigned char> satellite_shared = derive_x25519_shared_secret(
        satellite_keypair,
        ground_public_loaded
    );

    if (ground_shared.empty() || satellite_shared.empty()) {
        std::cout << "[FAIL] ECDH shared secret derivation failed.\n";
        return 1;
    }

    std::cout << "Ground shared secret size: " << ground_shared.size() << " bytes\n";
    std::cout << "Satellite shared secret size: " << satellite_shared.size() << " bytes\n";

    if (secure_equal(ground_shared, satellite_shared)) {
        std::cout << "[PASS] Both sides derived the same ECDH shared secret.\n";
    } else {
        std::cout << "[FAIL] Shared secrets do not match.\n";
        return 1;
    }

    std::vector<unsigned char> ground_session_key = hkdf_sha256_session_key(ground_shared);
    std::vector<unsigned char> satellite_session_key = hkdf_sha256_session_key(satellite_shared);

    if (ground_session_key.size() != 32 || satellite_session_key.size() != 32) {
        std::cout << "[FAIL] HKDF session key derivation failed.\n";
        return 1;
    }

    print_hex("Ground session key HEX: ", ground_session_key);
    print_hex("Satellite session key HEX: ", satellite_session_key);

    if (secure_equal(ground_session_key, satellite_session_key)) {
        std::cout << "[PASS] HKDF produced identical 32-byte session keys.\n";
    } else {
        std::cout << "[FAIL] Session keys do not match.\n";
        return 1;
    }

    std::cout << "[PASS] Session key ready for ChaCha20-Poly1305 encryption.\n";
    std::cout << "=== Secure Handshake Test Complete ===\n";

    EVP_PKEY_free(ground_keypair);
    EVP_PKEY_free(satellite_keypair);
    EVP_PKEY_free(satellite_public_loaded);
    EVP_PKEY_free(ground_public_loaded);

    return 0;
}
