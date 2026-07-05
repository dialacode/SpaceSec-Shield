#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket failed");
        return 1;
    }

    sockaddr_in satAddr{};
    satAddr.sin_family = AF_INET;
    satAddr.sin_port = htons(9000);
    satAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&satAddr, sizeof(satAddr)) < 0) {
        perror("bind failed");
        return 1;
    }

    std::cout << "Satellite Node listening on port 9000..." << std::endl;

    while (true) {
        char buffer[1024] = {0};

        sockaddr_in groundAddr{};
        socklen_t addrLen = sizeof(groundAddr);

        ssize_t n = recvfrom(
            sock,
            buffer,
            sizeof(buffer) - 1,
            0,
            (struct sockaddr*)&groundAddr,
            &addrLen
        );

        if (n < 0) {
            perror("recvfrom failed");
            continue;
        }

        buffer[n] = '\0';

        std::cout << "Received Command: " << buffer << std::endl;

        // Process command (simulation)
        std::string response = "ACK: ";
        response += buffer;

        sendto(
            sock,
            response.c_str(),
            response.size(),
            0,
            (struct sockaddr*)&groundAddr,
            addrLen
        );
    }

    close(sock);
    return 0;
}
