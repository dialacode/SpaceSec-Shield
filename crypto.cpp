#include "crypto.hpp"
#include <openssl/evp.h>

bool encrypt_chacha20_poly1305(
    const std::vector<unsigned char>& key,
    const unsigned char* nonce,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad,
    std::vector<unsigned char>& ciphertext,
    std::vector<unsigned char>& tag
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int ciphertext_len = 0;

    ciphertext.resize(plaintext.size());
    tag.resize(16);

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return true;
}

bool decrypt_chacha20_poly1305(
    const std::vector<unsigned char>& key,
    const unsigned char* nonce,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& tag,
    std::vector<unsigned char>& plaintext_out
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int plaintext_len = 0;

    plaintext_out.resize(ciphertext.size());

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    if (EVP_DecryptUpdate(ctx, plaintext_out.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int ok = EVP_DecryptFinal_ex(ctx, plaintext_out.data() + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ok <= 0) {
        plaintext_out.clear();
        return false;
    }

    plaintext_len += len;
    plaintext_out.resize(plaintext_len);
    return true;
}
