#pragma once

#include "packet.hpp"
#include <unordered_set>
#include <string>
#include <cstdint>

class AntiReplay {
private:
    std::unordered_set<std::string> seen_nonces;
    uint64_t window_ms;

    std::string make_nonce_key(uint32_t session_id, const std::array<unsigned char, NONCE_SIZE>& nonce) const;

public:
    explicit AntiReplay(uint64_t freshness_window_ms = 30000);

    bool is_fresh(uint64_t packet_timestamp_ms, uint64_t current_time_ms) const;

    bool is_duplicate(uint32_t session_id, const std::array<unsigned char, NONCE_SIZE>& nonce) const;

    void mark_seen(uint32_t session_id, const std::array<unsigned char, NONCE_SIZE>& nonce);
};
