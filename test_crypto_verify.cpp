#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>

void print_hex(const std::string& label, const std::vector<unsigned char>& data) {
    std::cout << label;
    for (unsigned char c : data) {
        printf("%02x", c);
    }
    std::cout << "\n";
}

std::vector<unsigned char> encrypt_chacha20_poly1305(
    const std::vector<unsigned char>& key,
    const unsigned char* nonce,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad,
    std::vector<unsigned char>& tag
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;

    std::vector<unsigned char> ciphertext(plaintext.size());
    tag.resize(16);

    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce);

    EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data());

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);
    return ciphertext;
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
    int len = 0;

    plaintext_out.resize(ciphertext.size());

    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce);

    EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());

    EVP_DecryptUpdate(ctx, plaintext_out.data(), &len, ciphertext.data(), ciphertext.size());
    int plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag.data());

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

int main() {
    std::vector<unsigned char> key(32, 0x01);

    unsigned char nonce[12] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01
    };

    std::string command = "CMD:TAKE_IMAGE";
    std::vector<unsigned char> plaintext(command.begin(), command.end());

    std::string header = "session_id=1;timestamp=123456789;nonce=000000000001;";
    std::vector<unsigned char> aad(header.begin(), header.end());

    std::vector<unsigned char> tag;
    std::vector<unsigned char> ciphertext = encrypt_chacha20_poly1305(
        key, nonce, plaintext, aad, tag
    );

    std::cout << "=== SpaceSec Shield Phase 3 Crypto Verification ===\n";
    std::cout << "Original Plaintext: " << command << "\n";
    print_hex("Ciphertext HEX: ", ciphertext);
    print_hex("Poly1305 Tag HEX: ", tag);

    std::vector<unsigned char> recovered;
    bool ok = decrypt_chacha20_poly1305(key, nonce, ciphertext, aad, tag, recovered);

    if (ok) {
        std::string recovered_text(recovered.begin(), recovered.end());
        std::cout << "[PASS] Valid packet decrypted successfully: " << recovered_text << "\n";
    } else {
        std::cout << "[FAIL] Valid packet was rejected.\n";
    }

    std::vector<unsigned char> tampered_ciphertext = ciphertext;
    tampered_ciphertext[0] ^= 0x01;

    ok = decrypt_chacha20_poly1305(key, nonce, tampered_ciphertext, aad, tag, recovered);

    if (!ok) {
        std::cout << "[PASS] Tampered ciphertext rejected.\n";
    } else {
        std::cout << "[FAIL] Tampered ciphertext accepted.\n";
    }

    std::vector<unsigned char> tampered_tag = tag;
    tampered_tag[0] ^= 0x01;

    ok = decrypt_chacha20_poly1305(key, nonce, ciphertext, aad, tampered_tag, recovered);

    if (!ok) {
        std::cout << "[PASS] Tampered tag rejected.\n";
    } else {
        std::cout << "[FAIL] Tampered tag accepted.\n";
    }

    std::vector<unsigned char> tampered_aad = aad;
    tampered_aad[0] ^= 0x01;

    ok = decrypt_chacha20_poly1305(key, nonce, ciphertext, tampered_aad, tag, recovered);

    if (!ok) {
        std::cout << "[PASS] Tampered header/AAD rejected.\n";
    } else {
        std::cout << "[FAIL] Tampered header/AAD accepted.\n";
    }

    std::cout << "=== Phase 3 Crypto Verification Complete ===\n";

    return 0;
}
