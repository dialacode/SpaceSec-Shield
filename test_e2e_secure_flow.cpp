#include "handshake.hpp"
#include "crypto.hpp"
#include "packet.hpp"
#include "anti_replay.hpp"

#include <openssl/crypto.h>
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

bool secure_equal(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::vector<unsigned char> establish_ground_session_key(
    EVP_PKEY* ground_keypair,
    const std::vector<unsigned char>& satellite_public_raw
) {
    EVP_PKEY* satellite_public = load_x25519_public_key(satellite_public_raw);
    if (!satellite_public) return {};

    std::vector<unsigned char> shared = derive_x25519_shared_secret(
        ground_keypair,
        satellite_public
    );

    EVP_PKEY_free(satellite_public);

    if (shared.empty()) return {};
    return hkdf_sha256_session_key(shared);
}

std::vector<unsigned char> establish_satellite_session_key(
    EVP_PKEY* satellite_keypair,
    const std::vector<unsigned char>& ground_public_raw
) {
    EVP_PKEY* ground_public = load_x25519_public_key(ground_public_raw);
    if (!ground_public) return {};

    std::vector<unsigned char> shared = derive_x25519_shared_secret(
        satellite_keypair,
        ground_public
    );

    EVP_PKEY_free(ground_public);

    if (shared.empty()) return {};
    return hkdf_sha256_session_key(shared);
}

std::vector<unsigned char> create_secure_command_packet(
    const std::vector<unsigned char>& session_key,
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
        session_key,
        packet.nonce.data(),
        plaintext,
        aad,
        packet.ciphertext,
        tag_vec
    );

    if (!ok) return {};

    std::copy(tag_vec.begin(), tag_vec.end(), packet.tag.begin());

    return serialize_packet(packet);
}

bool satellite_receive_packet(
    const std::vector<unsigned char>& raw_packet,
    const std::vector<unsigned char>& satellite_session_key,
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
        std::cout << "[REJECT] Expired timestamp.\n";
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
        satellite_session_key,
        packet.nonce.data(),
        packet.ciphertext,
        aad,
        tag,
        plaintext
    );

    if (!ok) {
        std::cout << "[REJECT] Authentication failed: tampered or forged packet.\n";
        return false;
    }

    replay_guard.mark_seen(packet.session_id, packet.nonce);
    recovered_command.assign(plaintext.begin(), plaintext.end());

    return true;
}

int main() {
    std::cout << "=== SpaceSec Shield Phase 3 End-to-End Secure Flow Test ===\n";

    EVP_PKEY* ground_keypair = generate_x25519_keypair();
    EVP_PKEY* satellite_keypair = generate_x25519_keypair();

    if (!ground_keypair || !satellite_keypair) {
        std::cout << "[FAIL] Failed to generate ephemeral X25519 keys.\n";
        return 1;
    }

    std::vector<unsigned char> ground_public = get_raw_public_key(ground_keypair);
    std::vector<unsigned char> satellite_public = get_raw_public_key(satellite_keypair);

    std::vector<unsigned char> ground_session_key =
        establish_ground_session_key(ground_keypair, satellite_public);

    std::vector<unsigned char> satellite_session_key =
        establish_satellite_session_key(satellite_keypair, ground_public);

    if (ground_session_key.empty() || satellite_session_key.empty()) {
        std::cout << "[FAIL] Session key establishment failed.\n";
        return 1;
    }

    if (secure_equal(ground_session_key, satellite_session_key)) {
        std::cout << "[PASS] Secure handshake established matching session keys.\n";
    } else {
        std::cout << "[FAIL] Session keys do not match.\n";
        return 1;
    }

    AntiReplay replay_guard(30000);

    std::array<unsigned char, NONCE_SIZE> nonce1 = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10
    };

    std::vector<unsigned char> secure_packet = create_secure_command_packet(
        ground_session_key,
        2026,
        now_ms(),
        nonce1,
        "CMD:CAPTURE_IMAGE"
    );

    std::string recovered;

    bool ok = satellite_receive_packet(
        secure_packet,
        satellite_session_key,
        replay_guard,
        recovered
    );

    if (ok) {
        std::cout << "[PASS] Satellite decrypted authenticated command: " << recovered << "\n";
    } else {
        std::cout << "[FAIL] Valid secure command was rejected.\n";
    }

    ok = satellite_receive_packet(
        secure_packet,
        satellite_session_key,
        replay_guard,
        recovered
    );

    if (!ok) {
        std::cout << "[PASS] Replay of the same packet was rejected.\n";
    } else {
        std::cout << "[FAIL] Replay packet was accepted.\n";
    }

    std::array<unsigned char, NONCE_SIZE> nonce2 = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x11
    };

    std::vector<unsigned char> tampered_packet = create_secure_command_packet(
        ground_session_key,
        2026,
        now_ms(),
        nonce2,
        "CMD:OPEN_PAYLOAD_DOOR"
    );

    if (!tampered_packet.empty()) {
        tampered_packet[HEADER_SIZE] ^= 0x01;
    }

    ok = satellite_receive_packet(
        tampered_packet,
        satellite_session_key,
        replay_guard,
        recovered
    );

    if (!ok) {
        std::cout << "[PASS] Tampered encrypted payload was rejected.\n";
    } else {
        std::cout << "[FAIL] Tampered encrypted payload was accepted.\n";
    }

    std::array<unsigned char, NONCE_SIZE> nonce3 = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x12
    };

    uint64_t old_timestamp = now_ms() - 60000;

    std::vector<unsigned char> expired_packet = create_secure_command_packet(
        ground_session_key,
        2026,
        old_timestamp,
        nonce3,
        "CMD:RESET_SYSTEM"
    );

    ok = satellite_receive_packet(
        expired_packet,
        satellite_session_key,
        replay_guard,
        recovered
    );

    if (!ok) {
        std::cout << "[PASS] Expired secure packet was rejected.\n";
    } else {
        std::cout << "[FAIL] Expired secure packet was accepted.\n";
    }

    std::cout << "=== End-to-End Secure Flow Test Complete ===\n";

    EVP_PKEY_free(ground_keypair);
    EVP_PKEY_free(satellite_keypair);

    return 0;
}
