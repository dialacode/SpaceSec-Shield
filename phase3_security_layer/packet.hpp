#pragma once

#include <array>
#include <vector>
#include <cstdint>
#include <cstddef>

constexpr std::size_t SESSION_ID_SIZE = 4;
constexpr std::size_t TIMESTAMP_SIZE  = 8;
constexpr std::size_t NONCE_SIZE      = 12;
constexpr std::size_t TAG_SIZE        = 16;
constexpr std::size_t HEADER_SIZE     = SESSION_ID_SIZE + TIMESTAMP_SIZE + NONCE_SIZE;

struct SecurePacket {
    uint32_t session_id;
    uint64_t timestamp_ms;
    std::array<unsigned char, NONCE_SIZE> nonce;
    std::vector<unsigned char> ciphertext;
    std::array<unsigned char, TAG_SIZE> tag;
};

std::vector<unsigned char> build_aad(const SecurePacket& packet);
std::vector<unsigned char> serialize_packet(const SecurePacket& packet);
bool deserialize_packet(const std::vector<unsigned char>& data, SecurePacket& packet);
