#include <cstddef>
#include "anti_replay.hpp"
#include <sstream>
#include <iomanip>

AntiReplay::AntiReplay(uint64_t freshness_window_ms)
    : window_ms(freshness_window_ms) {}

std::string AntiReplay::make_nonce_key(
    uint32_t session_id,
    const std::array<unsigned char, NONCE_SIZE>& nonce
) const {
    std::ostringstream oss;
    oss << session_id << ":";

    for (unsigned char b : nonce) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }

    return oss.str();
}

bool AntiReplay::is_fresh(uint64_t packet_timestamp_ms, uint64_t current_time_ms) const {
    uint64_t diff;

    if (current_time_ms >= packet_timestamp_ms) {
        diff = current_time_ms - packet_timestamp_ms;
    } else {
        diff = packet_timestamp_ms - current_time_ms;
    }

    return diff <= window_ms;
}

bool AntiReplay::is_duplicate(
    uint32_t session_id,
    const std::array<unsigned char, NONCE_SIZE>& nonce
) const {
    std::string key = make_nonce_key(session_id, nonce);
    return seen_nonces.find(key) != seen_nonces.end();
}

void AntiReplay::mark_seen(
    uint32_t session_id,
    const std::array<unsigned char, NONCE_SIZE>& nonce
) {
    std::string key = make_nonce_key(session_id, nonce);
    seen_nonces.insert(key);
}
