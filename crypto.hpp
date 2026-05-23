#pragma once
#include <vector>

bool encrypt_chacha20_poly1305(
    const std::vector<unsigned char>& key,
    const unsigned char* nonce,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad,
    std::vector<unsigned char>& ciphertext,
    std::vector<unsigned char>& tag
);

bool decrypt_chacha20_poly1305(
    const std::vector<unsigned char>& key,
    const unsigned char* nonce,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& tag,
    std::vector<unsigned char>& plaintext_out
);
