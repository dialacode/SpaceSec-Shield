#include "dashboard_client.hpp"

#include <sstream>
#include <iomanip>
#include <cstring>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <cerrno>

// Where to POST events. Defaults to the Ground Station in the space-net lab.
static std::string g_host = "192.168.10.10";
static int         g_port = 5000;

// Hard cap on how long a single POST may take, so a dead dashboard can never
// stall the Satellite's packet loop.
static const long TIMEOUT_US = 300000; // 300 ms

void dashboard_init(const std::string& host, int port) {
    g_host = host;
    g_port = port;
}

// 2026 -> "07EA" (4 hex digits, uppercase) to match the schema's "A1B2" style.
static std::string hex_session(uint32_t id) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex
        << std::setw(4) << std::setfill('0') << (id & 0xFFFF);
    return oss.str();
}

void post_security_event(
    const std::string& type,
    const std::string& reason,
    uint32_t session_id,
    long latency_ms,
    const std::string& severity
) {
    // 1) Build the JSON body (matches templates/Phase-5 event schema).
    std::ostringstream body;
    body << "{"
         << "\"type\":\""       << type                     << "\","
         << "\"reason\":\""      << reason                   << "\","
         << "\"session_id\":\""  << hex_session(session_id)  << "\","
         << "\"latency_ms\":"    << latency_ms               << ","
         << "\"severity\":\""    << severity                 << "\""
         << "}";
    const std::string json = body.str();

    // 2) Wrap it in a minimal HTTP/1.1 POST request.
    std::ostringstream req;
    req << "POST /api/event HTTP/1.1\r\n"
        << "Host: " << g_host << ":" << g_port << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << json.size() << "\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << json;
    const std::string request = req.str();

    // 3) Open a TCP socket to the dashboard.
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(g_port);
    if (inet_pton(AF_INET, g_host.c_str(), &addr.sin_addr) != 1) {
        close(sock);
        return;
    }

    // Non-blocking connect + select() timeout: a down dashboard fails fast
    // instead of hanging on the default TCP connect timeout.
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(sock, (sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        timeval tv{};
        tv.tv_sec  = 0;
        tv.tv_usec = TIMEOUT_US;
        if (select(sock + 1, nullptr, &wfds, nullptr, &tv) <= 0) {
            close(sock);
            return; // connect timed out
        }
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) {
            close(sock);
            return; // connect failed
        }
    } else if (rc < 0) {
        close(sock);
        return;
    }

    // Back to blocking for the (short) send/recv, with send/recv timeouts.
    fcntl(sock, F_SETFL, flags);
    timeval to{};
    to.tv_sec  = 0;
    to.tv_usec = TIMEOUT_US;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

    // 4) Send the request and drain the response (discarded — fire and forget).
    ssize_t sent = send(sock, request.data(), request.size(), 0);
    (void)sent;

    char buf[256];
    while (recv(sock, buf, sizeof(buf), 0) > 0) {
        // discard dashboard's 200 OK
    }

    close(sock);
}
