#pragma once

#include <string>
#include <cstdint>

// ---------------------------------------------------------------------------
// SpaceSec Shield · Phase 5 — Satellite-side dashboard hook
//
// A tiny, DEPENDENCY-FREE HTTP client. It sends one security event as JSON to
// the Flask dashboard's /api/event endpoint using a raw TCP socket, so the
// build does NOT need libcurl. It is BEST-EFFORT: if the dashboard is down or
// slow it fails silently within ~300 ms and never blocks the Satellite Node.
// ---------------------------------------------------------------------------

// Configure where the dashboard lives (Ground Station / monitor VM).
// Default: 192.168.10.10:5000 (matches the space-net lab).
void dashboard_init(const std::string& host, int port);

// Post a single packet-decision event. Matches the Phase 5 JSON schema:
//   { "type", "reason", "session_id", "latency_ms", "severity", "timestamp" }
//
//   type      : "ACCEPTED" | "REJECTED"
//   reason    : "OK" | "TAG_FAIL" | "REPLAY_TS" | "DUP_NONCE" | "DECRYPT_FAIL" | "BAD_FORMAT"
//   session_id: numeric session id (sent as a 4-digit hex string, e.g. 2026 -> "07EA")
//   latency_ms: now - packet.timestamp_ms (rough one-way latency)
//   severity  : "LOW" | "MEDIUM" | "CRITICAL"
void post_security_event(
    const std::string& type,
    const std::string& reason,
    uint32_t session_id,
    long latency_ms,
    const std::string& severity
);
