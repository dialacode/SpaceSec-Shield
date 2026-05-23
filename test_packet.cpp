#include "crypto.hpp"
#include "packet.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <algorithm>
#include <cstdio>

void print_hex(const std::string& label, const std::vector<unsigned char>& data) {
    std::cout << label;
    for (unsigned char c : data) {
        printf("%02x", c);
    }
    std::cout << "\n";
}

uint64_t now_ms() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();

    return static_cast<uint64_t>(ms);
}

int main() {
    std::cout << "=== SpaceSec Shield Phase 3 Packet Structure Test ===\n";

    std::vector<unsigned char> key(32, 0x01);

    SecurePacket packet;
    packet.session_id = 7;
    packet.timestamp_ms = now_ms();
    packet.nonce = {0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x02};

    std::string command = "CMD:DEPLOY_ANTENNA";
    std::vector<unsigned char> plaintext(command.begin(), command.end());

    std::vector<unsigned char> aad = build_aad(packet);
    std::vector<unsigned char> tag_vec;

    bool enc_ok = encrypt_chacha20_poly1305(
        key,
        packet.nonce.data(),
        plaintext,
        aad,
        packet.ciphertext,
        tag_vec
    );

    if (!enc_ok) {
        std::cout << "[FAIL] Encryption failed.\n";
        return 1;
    }

    std::copy(tag_vec.begin(), tag_vec.end(), packet.tag.begin());

    std::vector<unsigned char> serialized = serialize_packet(packet);

    std::cout << "Session ID: " << packet.session_id << "\n";
    std::cout << "Timestamp ms: " << packet.timestamp_ms << "\n";
    std::cout << "Packet size bytes: " << serialized.size() << "\n";
    std::cout << "Header size bytes: " << HEADER_SIZE << "\n";
    std::cout << "Tag size bytes: " << TAG_SIZE << "\n";
    print_hex("Serialized Packet HEX: ", serialized);

    SecurePacket received;
    bool parse_ok = deserialize_packet(serialized, received);

    if (!parse_ok) {
        std::cout << "[FAIL] Packet deserialization failed.\n";
        return 1;
    }

    std::vector<unsigned char> received_aad = build_aad(received);
    std::vector<unsigned char> received_tag(received.tag.begin(), received.tag.end());

    std::vector<unsigned char> recovered;
    bool dec_ok = decrypt_chacha20_poly1305(
        key,
        received.nonce.data(),
        received.ciphertext,
        received_aad,
        received_tag,
        recovered
    );

    if (dec_ok) {
        std::string recovered_text(recovered.begin(), recovered.end());
        std::cout << "[PASS] Packet decrypted successfully: " << recovered_text << "\n";
    } else {
        std::cout << "[FAIL] Valid packet rejected.\n";
    }

    std::vector<unsigned char> tampered_header = serialized;
    tampered_header[0] ^= 0x01;

    SecurePacket tampered_header_packet;
    deserialize_packet(tampered_header, tampered_header_packet);

    std::vector<unsigned char> tampered_header_aad = build_aad(tampered_header_packet);
    std::vector<unsigned char> tampered_header_tag(
        tampered_header_packet.tag.begin(),
        tampered_header_packet.tag.end()
    );

    dec_ok = decrypt_chacha20_poly1305(
        key,
        tampered_header_packet.nonce.data(),
        tampered_header_packet.ciphertext,
        tampered_header_aad,
        tampered_header_tag,
        recovered
    );

    if (!dec_ok) {
        std::cout << "[PASS] Tampered packet header rejected.\n";
    } else {
        std::cout << "[FAIL] Tampered packet header accepted.\n";
    }

    std::vector<unsigned char> tampered_payload = serialized;
    tampered_payload[HEADER_SIZE] ^= 0x01;

    SecurePacket tampered_payload_packet;
    deserialize_packet(tampered_payload, tampered_payload_packet);

    std::vector<unsigned char> tampered_payload_aad = build_aad(tampered_payload_packet);
    std::vector<unsigned char> tampered_payload_tag(
        tampered_payload_packet.tag.begin(),
        tampered_payload_packet.tag.end()
    );

    dec_ok = decrypt_chacha20_poly1305(
        key,
        tampered_payload_packet.nonce.data(),
        tampered_payload_packet.ciphertext,
        tampered_payload_aad,
        tampered_payload_tag,
        recovered
    );

    if (!dec_ok) {
        std::cout << "[PASS] Tampered packet payload rejected.\n";
    } else {
        std::cout << "[FAIL] Tampered packet payload accepted.\n";
    }

    std::vector<unsigned char> tampered_tag = serialized;
    tampered_tag[tampered_tag.size() - 1] ^= 0x01;

    SecurePacket tampered_tag_packet;
    deserialize_packet(tampered_tag, tampered_tag_packet);

    std::vector<unsigned char> tampered_tag_aad = build_aad(tampered_tag_packet);
    std::vector<unsigned char> tampered_tag_vec(
        tampered_tag_packet.tag.begin(),
        tampered_tag_packet.tag.end()
    );

    dec_ok = decrypt_chacha20_poly1305(
        key,
        tampered_tag_packet.nonce.data(),
        tampered_tag_packet.ciphertext,
        tampered_tag_aad,
        tampered_tag_vec,
        recovered
    );

    if (!dec_ok) {
        std::cout << "[PASS] Tampered packet tag rejected.\n";
    } else {
        std::cout << "[FAIL] Tampered packet tag accepted.\n";
    }

    std::cout << "=== Packet Structure Test Complete ===\n";

    return 0;
}
