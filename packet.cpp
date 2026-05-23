#include "packet.hpp"

static void write_u32_be(std::vector<unsigned char>& out, uint32_t value) {
    out.push_back((value >> 24) & 0xFF);
    out.push_back((value >> 16) & 0xFF);
    out.push_back((value >> 8) & 0xFF);
    out.push_back(value & 0xFF);
}

static void write_u64_be(std::vector<unsigned char>& out, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out.push_back((value >> (i * 8)) & 0xFF);
    }
}

static uint32_t read_u32_be(const std::vector<unsigned char>& data, size_t offset) {
    return ((uint32_t)data[offset] << 24) |
           ((uint32_t)data[offset + 1] << 16) |
           ((uint32_t)data[offset + 2] << 8) |
           ((uint32_t)data[offset + 3]);
}

static uint64_t read_u64_be(const std::vector<unsigned char>& data, size_t offset) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | data[offset + i];
    }
    return value;
}

std::vector<unsigned char> build_aad(const SecurePacket& packet) {
    std::vector<unsigned char> aad;

    write_u32_be(aad, packet.session_id);
    write_u64_be(aad, packet.timestamp_ms);

    for (unsigned char b : packet.nonce) {
        aad.push_back(b);
    }

    return aad;
}

std::vector<unsigned char> serialize_packet(const SecurePacket& packet) {
    std::vector<unsigned char> out = build_aad(packet);

    out.insert(out.end(), packet.ciphertext.begin(), packet.ciphertext.end());
    out.insert(out.end(), packet.tag.begin(), packet.tag.end());

    return out;
}

bool deserialize_packet(const std::vector<unsigned char>& data, SecurePacket& packet) {
    if (data.size() < HEADER_SIZE + TAG_SIZE) {
        return false;
    }

    packet.session_id = read_u32_be(data, 0);
    packet.timestamp_ms = read_u64_be(data, 4);

    size_t offset = 12;

    for (size_t i = 0; i < NONCE_SIZE; ++i) {
        packet.nonce[i] = data[offset + i];
    }

    offset += NONCE_SIZE;

    size_t ciphertext_len = data.size() - HEADER_SIZE - TAG_SIZE;

    packet.ciphertext.assign(
        data.begin() + HEADER_SIZE,
        data.begin() + HEADER_SIZE + ciphertext_len
    );

    for (size_t i = 0; i < TAG_SIZE; ++i) {
        packet.tag[i] = data[HEADER_SIZE + ciphertext_len + i];
    }

    return true;
}
