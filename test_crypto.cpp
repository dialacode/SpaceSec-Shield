#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <cstring>

int main() {
    std::vector<unsigned char> key(32, 0x01);     // 32-byte test key
    unsigned char nonce[12] = {0};                // 12-byte nonce
    unsigned char tag[16];                        // Poly1305 tag

    std::string message = "CMD:TAKE_IMAGE";
    std::vector<unsigned char> plaintext(message.begin(), message.end());

    std::string header = "session=1;timestamp=123456;";
    std::vector<unsigned char> aad(header.begin(), header.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        std::cerr << "Failed to create context\n";
        return 1;
    }

    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce);

    int len = 0;

    EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());

    std::vector<unsigned char> ciphertext(plaintext.size());

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);

    std::cout << "Plaintext: " << message << "\n";

    std::cout << "Ciphertext HEX: ";
    for (unsigned char c : ciphertext) {
        printf("%02x", c);
    }

    std::cout << "\nTag HEX: ";
    for (unsigned char c : tag) {
        printf("%02x", c);
    }

    std::cout << "\nEncryption test successful.\n";

    return 0;
}
