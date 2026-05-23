#include "handshake.hpp"

#include <openssl/kdf.h>
#include <cstring>
#include <iostream>

EVP_PKEY* generate_x25519_keypair() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx) return nullptr;

    EVP_PKEY* keypair = nullptr;

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    if (EVP_PKEY_keygen(pctx, &keypair) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(pctx);
    return keypair;
}

std::vector<unsigned char> get_raw_public_key(EVP_PKEY* keypair) {
    std::vector<unsigned char> public_key(32);
    size_t public_key_len = public_key.size();

    if (EVP_PKEY_get_raw_public_key(keypair, public_key.data(), &public_key_len) != 1) {
        return {};
    }

    public_key.resize(public_key_len);
    return public_key;
}

EVP_PKEY* load_x25519_public_key(const std::vector<unsigned char>& raw_public_key) {
    if (raw_public_key.size() != 32) {
        return nullptr;
    }

    return EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        nullptr,
        raw_public_key.data(),
        raw_public_key.size()
    );
}

std::vector<unsigned char> derive_x25519_shared_secret(
    EVP_PKEY* my_private_key,
    EVP_PKEY* peer_public_key
) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(my_private_key, nullptr);
    if (!ctx) return {};

    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_public_key) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    size_t secret_len = 0;

    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    std::vector<unsigned char> shared_secret(secret_len);

    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);

    shared_secret.resize(secret_len);
    return shared_secret;
}

std::vector<unsigned char> hkdf_sha256_session_key(
    const std::vector<unsigned char>& shared_secret
) {
    std::vector<unsigned char> session_key(32);
    size_t session_key_len = session_key.size();

    const unsigned char salt[] = "spacesec-salt";
    const unsigned char info[] = "spacesec-phase3-session-key";

    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!kctx) return {};

    if (EVP_PKEY_derive_init(kctx) != 1) {
        EVP_PKEY_CTX_free(kctx);
        return {};
    }

    if (EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) != 1) {
        EVP_PKEY_CTX_free(kctx);
        return {};
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(kctx, salt, std::strlen((const char*)salt)) != 1) {
        EVP_PKEY_CTX_free(kctx);
        return {};
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(kctx, shared_secret.data(), shared_secret.size()) != 1) {
        EVP_PKEY_CTX_free(kctx);
        return {};
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(kctx, info, std::strlen((const char*)info)) != 1) {
        EVP_PKEY_CTX_free(kctx);
        return {};
    }

    if (EVP_PKEY_derive(kctx, session_key.data(), &session_key_len) != 1) {
        EVP_PKEY_CTX_free(kctx);
        return {};
    }

    EVP_PKEY_CTX_free(kctx);

    session_key.resize(session_key_len);
    return session_key;
}
