#include "handshake.hpp"
#include "crypto.hpp"
#include "packet.hpp"

#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <algorithm>

uint64_t now_ms() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();
    return static_cast<uint64_t>(ms);
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

void send_packet(
    int sockfd,
    sockaddr_in& sat_addr,
    const std::vector<unsigned char>& packet,
    const std::string& label
) {
    sendto(
        sockfd,
        packet.data(),
        packet.size(),
        0,
        (sockaddr*)&sat_addr,
        sizeof(sat_addr)
    );

    std::cout << "[SEND] " << label << " | Size: " << packet.size() << " bytes\n";
}

int main() {
    std::cout << "=== SpaceSec Shield Secure Ground Station ===\n";

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "[FAIL] Socket creation failed.\n";
        return 1;
    }

    sockaddr_in sat_addr{};
    sat_addr.sin_family = AF_INET;
    sat_addr.sin_port = htons(9000);
    inet_pton(AF_INET, "192.168.10.20", &sat_addr.sin_addr);

    EVP_PKEY* ground_keypair = generate_x25519_keypair();
    std::vector<unsigned char> ground_public = get_raw_public_key(ground_keypair);

    sendto(
        sockfd,
        ground_public.data(),
        ground_public.size(),
        0,
        (sockaddr*)&sat_addr,
        sizeof(sat_addr)
    );

    std::cout << "[SEND] Ground Station public key sent.\n";

    unsigned char buffer[2048];
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);

    ssize_t received = recvfrom(
        sockfd,
        buffer,
        sizeof(buffer),
        0,
        (sockaddr*)&from_addr,
        &from_len
    );

    if (received != 32) {
        std::cerr << "[FAIL] Expected 32-byte Satellite public key.\n";
        EVP_PKEY_free(ground_keypair);
        close(sockfd);
        return 1;
    }

    std::vector<unsigned char> satellite_public(buffer, buffer + received);
    EVP_PKEY* satellite_public_loaded = load_x25519_public_key(satellite_public);

    std::vector<unsigned char> shared = derive_x25519_shared_secret(
        ground_keypair,
        satellite_public_loaded
    );

    std::vector<unsigned char> session_key = hkdf_sha256_session_key(shared);

    if (session_key.size() != 32) {
        std::cerr << "[FAIL] Session key derivation failed.\n";
        EVP_PKEY_free(ground_keypair);
        EVP_PKEY_free(satellite_public_loaded);
        close(sockfd);
        return 1;
    }

    std::cout << "[PASS] Secure handshake completed.\n";
    std::cout << "[PASS] 32-byte session key established.\n";

    std::array<unsigned char, NONCE_SIZE> nonce1 = {
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x20
    };

    std::vector<unsigned char> valid_packet = create_secure_command_packet(
        session_key,
        2026,
        now_ms(),
        nonce1,
        "CMD:CAPTURE_IMAGE"
    );

    send_packet(sockfd, sat_addr, valid_packet, "Valid encrypted command");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    send_packet(sockfd, sat_addr, valid_packet, "Replay attack: same packet resent");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    std::array<unsigned char, NONCE_SIZE> nonce2 = {
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x21
    };

    std::vector<unsigned char> tampered_packet = create_secure_command_packet(
        session_key,
        2026,
        now_ms(),
        nonce2,
        "CMD:OPEN_PAYLOAD_DOOR"
    );

    if (!tampered_packet.empty()) {
        tampered_packet[HEADER_SIZE] ^= 0x01;
    }

    send_packet(sockfd, sat_addr, tampered_packet, "Tampered encrypted payload");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    std::array<unsigned char, NONCE_SIZE> nonce3 = {
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x22
    };

    std::vector<unsigned char> expired_packet = create_secure_command_packet(
        session_key,
        2026,
        now_ms() - 60000,
        nonce3,
        "CMD:RESET_SYSTEM"
    );

    send_packet(sockfd, sat_addr, expired_packet, "Expired timestamp packet");

    std::cout << "\n=== Ground Station Test Complete ===\n";

    EVP_PKEY_free(ground_keypair);
    EVP_PKEY_free(satellite_public_loaded);
    close(sockfd);

    return 0;
}
