#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <csignal>
#include <string>
#include <fstream>
#include <cstring>

#include "utils.cpp"


auth_type authenticate(std::string username, std::string password) {
    // Return true for guests, but return a different auth response to server M
    if (username == "guest" && password == encrypt_password("guest")) return auth_type::GUEST;
    std::ifstream file("members.txt");
    std::string line;
    while (std::getline(file, line)) {
        std::vector<std::string> res = split(line, " ");
        if (res[0] == username && res[1] == password) return auth_type::MEMBER;
    }
    return auth_type::ANONYMOUS;
}

int main() {
    // Server A socket
    int sock_fd;
    // Server M socket
    int udp_m_sock_fd;
    struct addrinfo *serv_info, *udp_m_serv_info;
    struct sockaddr_storage client_addr;
    socklen_t addr_len;
    struct sigaction sa;

    struct addrinfo hints = get_hints(false);

    // Taken from Beej’s Guide to Network Programming (v3.1.12), section 6.1
    if (getaddrinfo(nullptr, PORT_A, &hints, &serv_info) != 0) {
        std::cout << "Server A: getaddrinfo() failed" << std::endl;
        return 1;
    }
    if (getaddrinfo(nullptr, PORT_M_UDP, &hints, &udp_m_serv_info) != 0) {
        std::cout << "Server A: getaddrinfo() for connecting to server M failed" << std::endl;
    }

    sock_fd = bind_first(serv_info, false);
    // Make a UDP socket for server M
    // Taken from Beej’s Guide to Network Programming (v3.1.12), section 6.3
    struct addrinfo *m_addrinfo;
    for (m_addrinfo = udp_m_serv_info; m_addrinfo != nullptr; m_addrinfo = m_addrinfo->ai_next) {
        if ((udp_m_sock_fd = socket(m_addrinfo->ai_family, m_addrinfo->ai_socktype, m_addrinfo->ai_protocol)) == -1) {
            perror("Server A: socket() for UDP with M failed");
            continue;
        }
        break;
    }
    if (m_addrinfo == nullptr) {
        std::cout << "Server A: UDP socket() for server M failed" << std::endl;
        return 2;
    }

    // Taken from Beej’s Guide to Network Programming (v3.1.12), section 6.1
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        perror("Server A: sigaction");
        exit(1);
    }
    std::cout << "Server A is up and running using UDP on port " << PORT_A << std::endl;

    while (1) {
        char client_message[MAX_REQUEST_SIZE] = "";
        char auth_response[MAX_RESPONSE_SIZE] = "";
        addr_len = sizeof client_addr;
        // Server M sends an auth string of the format "auth <username> <password>".
        recvfrom(sock_fd, client_message, MAX_REQUEST_SIZE-1, 0, (struct sockaddr *)&client_addr, &addr_len);
        std::string request_string(client_message);
        std::vector<std::string> request;
        request = split(request_string, " ");
        std::string username = request[1];
        std::string password = request[2];

        std::cout << "Server A received username " << username << " and password ******" << std::endl;
        auth_type auth = authenticate(username, password);
        if (auth == auth_type::MEMBER) {
            strcpy(auth_response, "success");
            std::cout << "Member " << username << " has been authenticated" << std::endl;
        }
        else if (auth == auth_type::GUEST) {
            strcpy(auth_response, "auth guest");
        }
        else {
            strcpy(auth_response, "auth failed");
            std::cout << "The username " << username << " and password ****** is incorrect" << std::endl;
        }
        sendto(udp_m_sock_fd, auth_response, MAX_RESPONSE_SIZE-1, 0, udp_m_serv_info->ai_addr, udp_m_serv_info->ai_addrlen);


        if (request_string == "q") break;
    }
    close(sock_fd);
    return 0;
}