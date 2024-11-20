#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <csignal>
#include <string>
#include <fstream>
#include <cstring>
#include <string>
#include <vector>

#include "utils.cpp"


/**
 * Return a comma-separated string containing the user's files
 */
std::string get_user_files(std::string username) {
    std::ifstream file("filenames.txt");
    std::string line;
    std::string files = "";
    int line_count = 0;
    while (std::getline(file, line)) {
        std::vector<std::string> res = split(line, " ");
        line_count += 1;
        if (res[0] == username) {
            files += res[1] + ",";
        }
    }
    if (line_count == 0) return "repository 404";
    if (files.size() == 0) return "username 404";
    return files.substr(0, files.size()-1);
}


int main() {
    // Server R socket
    int sock_fd;
    // Server M socket
    int udp_m_sock_fd;
    struct addrinfo *serv_info, *udp_m_serv_info;
    struct sockaddr_storage client_addr;
    socklen_t addr_len;
    struct sigaction sa;

    struct addrinfo hints = get_hints(false);

    if (getaddrinfo(nullptr, PORT_R, &hints, &serv_info) != 0) {
        std::cout << "Server A: getaddrinfo() failed" << std::endl;
        return 1;
    }
    if (getaddrinfo(nullptr, PORT_M_UDP, &hints, &udp_m_serv_info) != 0) {
        std::cout << "Server A: getaddrinfo() for connecting to server M failed" << std::endl;
    }

    sock_fd = bind_first(serv_info, false);
    // Make a UDP socket for server M
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

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        perror("Server A: sigaction");
        exit(1);
    }
    std::cout << "Server R is up and running using UDP on port " << PORT_R << std::endl;

    while (1) {
        char client_message[MAX_REQUEST_SIZE] = "";
        char client_response[MAX_RESPONSE_SIZE] = "";
        addr_len = sizeof client_addr;
        recvfrom(sock_fd, client_message, MAX_REQUEST_SIZE-1, 0, (struct sockaddr *)&client_addr, &addr_len);
        std::string request_string(client_message);
        std::cout << "----Server R received request: " << request_string << std::endl;
        std::cout << "Server R has received a lookup request from the main server" << std::endl;

        std::vector<std::string> res = split(request_string, " ");
        std::string response = get_user_files(res[1]);
        strcpy(client_response, response.c_str());
        sendto(udp_m_sock_fd, client_response, MAX_RESPONSE_SIZE-1, 0, udp_m_serv_info->ai_addr, udp_m_serv_info->ai_addrlen);
        std::cout << "Server R has finished sending the response to the main server" << std::endl;

        if (request_string == "q") break;
    }
    close(sock_fd);
    return 0;
}