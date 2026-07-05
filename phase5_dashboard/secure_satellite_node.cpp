#include "handshake.hpp"
#include "crypto.hpp"
#include "packet.hpp"
#include "anti_replay.hpp"
#include "dashboard_client.hpp"   // Phase 5: report each decision to the dashboard

#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>

uint64_t now_ms() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();
    return static_cast<uint64_t>(ms);
}

bool process_secure_packet(
    const std::vector<unsigned char>& raw_packet,
    const std::vector<unsigned char>& session_key,
    AntiReplay& replay_guard,
    int sockfd,
    sockaddr_in& ground_addr,
    socklen_t ground_len
) {
    SecurePacket packet;

    if (!deserialize_packet(raw_packet, packet)) {
        std::cout << "[REJECT] Invalid packet format.\n";
        // Malformed / truncated packet (e.g. a raw nc injection).
        post_security_event("REJECTED", "BAD_FORMAT", 0, 0, "MEDIUM");
        return false;
    }

    // Rough one-way latency: how stale the packet is when we look at it.
    long latency_ms = (long)now_ms() - (long)packet.timestamp_ms;

    if (!replay_guard.is_fresh(packet.timestamp_ms, now_ms())) {
        std::cout << "[REJECT] Expired timestamp.\n";
        post_security_event("REJECTED", "REPLAY_TS",
                            packet.session_id, latency_ms, "CRITICAL");
        return false;
    }

    if (replay_guard.is_duplicate(packet.session_id, packet.nonce)) {
        std::cout << "[REJECT] Replay detected: duplicate nonce.\n";
        post_security_event("REJECTED", "DUP_NONCE",
                            packet.session_id, latency_ms, "CRITICAL");
        return false;
    }

    std::vector<unsigned char> aad = build_aad(packet);
    std::vector<unsigned char> tag(packet.tag.begin(), packet.tag.end());
    std::vector<unsigned char> plaintext;

    bool ok = decrypt_chacha20_poly1305(
        session_key,
        packet.nonce.data(),
        packet.ciphertext,
        aad,
        tag,
        plaintext
    );

    if (!ok) {
        std::cout << "[REJECT] Authentication failed: tampered or forged packet.\n";
        post_security_event("REJECTED", "TAG_FAIL",
                            packet.session_id, latency_ms, "CRITICAL");
        return false;
    }

    replay_guard.mark_seen(packet.session_id, packet.nonce);

    std::string command(plaintext.begin(), plaintext.end());
    std::cout << "[ACCEPT] Authenticated command received: " << command << "\n";
    std::cout << "[EXECUTE] Command executed safely.\n";

    // Phase 5: report the accepted, authenticated command to the dashboard.
    post_security_event("ACCEPTED", "OK",
                        packet.session_id, latency_ms, "LOW");

    // Send ACK back ONLY after a successful, authenticated command.
    // Rejected packets get no ACK -> the Ground Station will time out.
    const char* ack = "ACK";
    sendto(sockfd, ack, 3, 0, (sockaddr*)&ground_addr, ground_len);
    std::cout << "[SEND] ACK sent to Ground Station.\n";

    return true;
}

int main() {
    std::cout << "=== SpaceSec Shield Secure Satellite Node ===\n";

    // Phase 5: where to push security events (Ground Station / monitor VM).
    // Change the IP/port here if the dashboard runs elsewhere.
    dashboard_init("192.168.10.10", 5000);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "[FAIL] Socket creation failed.\n";
        return 1;
    }

    sockaddr_in sat_addr{};
    sat_addr.sin_family = AF_INET;
    sat_addr.sin_addr.s_addr = INADDR_ANY;
    sat_addr.sin_port = htons(9000);

    if (bind(sockfd, (sockaddr*)&sat_addr, sizeof(sat_addr)) < 0) {
        std::cerr << "[FAIL] Bind failed.\n";
        close(sockfd);
        return 1;
    }

    std::cout << "[INFO] Listening on UDP port 9000...\n";
    std::cout << "[INFO] Wireshark filter: udp.port == 9000\n";

    unsigned char buffer[2048];
    sockaddr_in ground_addr{};
    socklen_t ground_len = sizeof(ground_addr);

    ssize_t received = recvfrom(
        sockfd,
        buffer,
        sizeof(buffer),
        0,
        (sockaddr*)&ground_addr,
        &ground_len
    );

    if (received != 32) {
        std::cerr << "[FAIL] Expected 32-byte Ground Station public key.\n";
        close(sockfd);
        return 1;
    }

    std::vector<unsigned char> ground_public(buffer, buffer + received);

    EVP_PKEY* satellite_keypair = generate_x25519_keypair();
    std::vector<unsigned char> satellite_public = get_raw_public_key(satellite_keypair);

    sendto(
        sockfd,
        satellite_public.data(),
        satellite_public.size(),
        0,
        (sockaddr*)&ground_addr,
        ground_len
    );

    EVP_PKEY* ground_public_loaded = load_x25519_public_key(ground_public);

    std::vector<unsigned char> shared = derive_x25519_shared_secret(
        satellite_keypair,
        ground_public_loaded
    );

    std::vector<unsigned char> session_key = hkdf_sha256_session_key(shared);

    if (session_key.size() != 32) {
        std::cerr << "[FAIL] Session key derivation failed.\n";
        EVP_PKEY_free(satellite_keypair);
        EVP_PKEY_free(ground_public_loaded);
        close(sockfd);
        return 1;
    }

    std::cout << "[PASS] Secure handshake completed.\n";
    std::cout << "[PASS] 32-byte session key established.\n";

    AntiReplay replay_guard(30000);

    while (true) {
        received = recvfrom(
            sockfd,
            buffer,
            sizeof(buffer),
            0,
            (sockaddr*)&ground_addr,
            &ground_len
        );

        if (received <= 0) {
            std::cout << "[REJECT] Empty packet received.\n";
            continue;
        }

        // A 32-byte packet is NOT a command — it is a Ground Station that
        // (re)started and is sending its public key for a fresh handshake.
        // Re-handshake instead of rejecting it as "Invalid packet format".
        if (received == 32) {
            std::cout << "\n[INFO] New handshake request detected (32-byte public key).\n";

            std::vector<unsigned char> new_ground_public(buffer, buffer + received);

            // Reply with our public key so the Ground Station can finish its handshake.
            sendto(
                sockfd,
                satellite_public.data(),
                satellite_public.size(),
                0,
                (sockaddr*)&ground_addr,
                ground_len
            );

            EVP_PKEY_free(ground_public_loaded);
            ground_public_loaded = load_x25519_public_key(new_ground_public);

            shared = derive_x25519_shared_secret(satellite_keypair, ground_public_loaded);
            session_key = hkdf_sha256_session_key(shared);

            // Reset the anti-replay state for the NEW session, otherwise the
            // new session's nonce (starting again at 0x20) would be flagged
            // as a duplicate from the previous session.
            replay_guard = AntiReplay(30000);

            std::cout << "[PASS] Re-handshake completed. New session key established.\n";
            continue;
        }

        std::vector<unsigned char> raw_packet(buffer, buffer + received);

        std::cout << "\n[INFO] UDP packet received. Size: "
                  << raw_packet.size() << " bytes\n";

        process_secure_packet(
            raw_packet,
            session_key,
            replay_guard,
            sockfd,
            ground_addr,
            ground_len
        );
    }

    std::cout << "\n=== Satellite Node Test Complete ===\n";

    EVP_PKEY_free(satellite_keypair);
    EVP_PKEY_free(ground_public_loaded);
    close(sockfd);

    return 0;
}
