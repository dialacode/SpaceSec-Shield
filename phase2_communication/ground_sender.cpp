#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket failed");
        return 1;
    }

    // Receive timeout
    timeval tv{};
    tv.tv_sec = 2;
    tv.tv_usec = 0;

    setsockopt(
        sock,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &tv,
        sizeof(tv)
    );

    sockaddr_in satAddr{};
    satAddr.sin_family = AF_INET;
    satAddr.sin_port = htons(9000);
    satAddr.sin_addr.s_addr = inet_addr("192.168.10.20");

    std::string command = "CMD: STATUS_CHECK";

    ssize_t sent = sendto(
        sock,
        command.c_str(),
        command.size(),
        0,
        (struct sockaddr*)&satAddr,
        sizeof(satAddr)
    );

    if (sent < 0) {
        perror("sendto failed");
        return 1;
    }

    std::cout << "Command sent: " << command << std::endl;

    char buffer[1024] = {0};

    sockaddr_in fromAddr{};
    socklen_t addrLen = sizeof(fromAddr);

    ssize_t n = recvfrom(
        sock,
        buffer,
        sizeof(buffer) - 1,
        0,
        (struct sockaddr*)&fromAddr,
        &addrLen
    );

    if (n < 0) {
        std::cout << "No response (timeout / packet lost)" << std::endl;
    } else {
        buffer[n] = '\0';
        std::cout << "Response received: " << buffer << std::endl;
    }

    close(sock);
    return 0;
}
