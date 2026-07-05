#include "crypto.hpp"
#include "packet.hpp"
#include "anti_replay.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <algorithm>

uint64_t now_ms() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();

    return static_cast<uint64_t>(ms);
}

bool receive_secure_packet(
    const std::vector<unsigned char>& raw_packet,
    const std::vector<unsigned char>& key,
    AntiReplay& replay_guard,
    std::string& recovered_command
) {
    SecurePacket packet;

    if (!deserialize_packet(raw_packet, packet)) {
        std::cout << "[REJECT] Invalid packet format.\n";
        return false;
    }

    uint64_t current_time = now_ms();

    if (!replay_guard.is_fresh(packet.timestamp_ms, current_time)) {
        std::cout << "[REJECT] Expired timestamp detected.\n";
        return false;
    }

    if (replay_guard.is_duplicate(packet.session_id, packet.nonce)) {
        std::cout << "[REJECT] Replay detected: duplicate nonce.\n";
        return false;
    }

    std::vector<unsigned char> aad = build_aad(packet);
    std::vector<unsigned char> tag(packet.tag.begin(), packet.tag.end());
    std::vector<unsigned char> plaintext;

    bool ok = decrypt_chacha20_poly1305(
        key,
        packet.nonce.data(),
        packet.ciphertext,
        aad,
        tag,
        plaintext
    );

    if (!ok) {
        std::cout << "[REJECT] Authentication failed: tampered packet.\n";
        return false;
    }

    replay_guard.mark_seen(packet.session_id, packet.nonce);

    recovered_command.assign(plaintext.begin(), plaintext.end());
    return true;
}

std::vector<unsigned char> create_packet(
    const std::vector<unsigned char>& key,
    uint32_t session_id,
    uint64_t timestamp_ms,
    std::array<unsigned char, NONCE_SIZE> nonce,
    const std::string& command
) {
    SecurePacket packet;
    packet.session_id = session_id;
    packet.timestamp_ms = timestamp_ms;
    packet.nonce = nonce;

    std::vector<unsigned char> plaintext(command.begin(), command.end());
    std::vector<unsigned char> aad = build_aad(packet);
    std::vector<unsigned char> tag_vec;

    bool ok = encrypt_chacha20_poly1305(
        key,
        packet.nonce.data(),
        plaintext,
        aad,
        packet.ciphertext,
        tag_vec
    );

    if (!ok) {
        std::cout << "[FAIL] Encryption failed while creating packet.\n";
        return {};
    }

    std::copy(tag_vec.begin(), tag_vec.end(), packet.tag.begin());

    return serialize_packet(packet);
}

int main() {
    std::cout << "=== SpaceSec Shield Phase 3 Anti-Replay Test ===\n";

    std::vector<unsigned char> key(32, 0x01);
    AntiReplay replay_guard(30000);

    std::array<unsigned char, NONCE_SIZE> nonce1 = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03
    };

    std::vector<unsigned char> valid_packet = create_packet(
        key,
        7,
        now_ms(),
        nonce1,
        "CMD:DEPLOY_SOLAR_PANEL"
    );

    std::string recovered;

    bool ok = receive_secure_packet(valid_packet, key, replay_guard, recovered);

    if (ok) {
        std::cout << "[PASS] Fresh packet accepted and decrypted: " << recovered << "\n";
    } else {
        std::cout << "[FAIL] Fresh packet rejected.\n";
    }

    ok = receive_secure_packet(valid_packet, key, replay_guard, recovered);

    if (!ok) {
        std::cout << "[PASS] Replay packet rejected.\n";
    } else {
        std::cout << "[FAIL] Replay packet accepted.\n";
    }

    std::array<unsigned char, NONCE_SIZE> nonce2 = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04
    };

    uint64_t old_timestamp = now_ms() - 60000;

    std::vector<unsigned char> expired_packet = create_packet(
        key,
        7,
        old_timestamp,
        nonce2,
        "CMD:RESET_SYSTEM"
    );

    ok = receive_secure_packet(expired_packet, key, replay_guard, recovered);

    if (!ok) {
        std::cout << "[PASS] Expired timestamp packet rejected.\n";
    } else {
        std::cout << "[FAIL] Expired timestamp packet accepted.\n";
    }

    std::array<unsigned char, NONCE_SIZE> nonce3 = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05
    };

    std::vector<unsigned char> tampered_packet = create_packet(
        key,
        7,
        now_ms(),
        nonce3,
        "CMD:CHANGE_ORBIT"
    );

    if (!tampered_packet.empty()) {
        tampered_packet[HEADER_SIZE] ^= 0x01;
    }

    ok = receive_secure_packet(tampered_packet, key, replay_guard, recovered);

    if (!ok) {
        std::cout << "[PASS] Tampered packet rejected before command execution.\n";
    } else {
        std::cout << "[FAIL] Tampered packet accepted.\n";
    }

    std::cout << "=== Anti-Replay Test Complete ===\n";

    return 0;
}
