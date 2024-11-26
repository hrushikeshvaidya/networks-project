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
 * Deploy the given list of files on deployed.txt
 * The files of other users remain unaffected.
 */
void deploy(std::string username, std::vector<std::string> files) {
    std::vector<std::string> deployedFiles;
    std::ifstream file("deployed.txt");
    if (file.good()) {
        // If the file exists, get a list of deployed files for other users
        // and NOT the current user
        std::string line;
        while (std::getline(file, line)) {
            std::vector<std::string> res = split(line, " ");
            if (res.size() < 2) continue;
            if (res[0] == username) continue;
            deployedFiles.push_back(line);
        }
    }
    // Add the current user's files to deployedFiles
    for (std::string line : files) {
        deployedFiles.push_back(username + " " + line);
    }
    file.close();
    // Write deployed.txt
    std::ofstream outfile("deployed.txt");
    for (std::string line : deployedFiles) {
        outfile << line + "\n";
    }
}

int main() {
    // Server D socket
    int sock_fd;
    // Server M socket
    int udp_m_sock_fd;
    struct addrinfo *serv_info, *udp_m_serv_info;
    struct sockaddr_storage client_addr;
    socklen_t addr_len;
    struct sigaction sa;

    struct addrinfo hints = get_hints(false);

    // Taken from Beej’s Guide to Network Programming (v3.1.12), section 6.1
    if (getaddrinfo(nullptr, PORT_D, &hints, &serv_info) != 0) {
        std::cout << "Server D: getaddrinfo() failed" << std::endl;
        return 1;
    }
    if (getaddrinfo(nullptr, PORT_M_UDP, &hints, &udp_m_serv_info) != 0) {
        std::cout << "Server D: getaddrinfo() for connecting to server M failed" << std::endl;
        return 1;
    }

    sock_fd = bind_first(serv_info, false);
    // Make a UDP socket for server M
    // Taken from Beej’s Guide to Network Programming (v3.1.12), section 6.3
    struct addrinfo *m_addrinfo;
    for (m_addrinfo = udp_m_serv_info; m_addrinfo != nullptr; m_addrinfo = m_addrinfo->ai_next) {
        if ((udp_m_sock_fd = socket(m_addrinfo->ai_family, m_addrinfo->ai_socktype, m_addrinfo->ai_protocol)) == -1) {
            perror("Server D: socket() for UDP with M failed");
            continue;
        }
        break;
    }
    if (m_addrinfo == nullptr) {
        std::cout << "Server D: UDP socket() for server M failed" << std::endl;
        return 2;
    }

    // Taken from Beej’s Guide to Network Programming (v3.1.12), section 6.1
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        perror("Server D: sigaction");
        exit(1);
    }
    std::cout << "Server D is up and running using UDP on port " << PORT_D << std::endl;

    while (1) {
        char client_message[MAX_REQUEST_SIZE] = "";
        addr_len = sizeof client_addr;

        recvfrom(sock_fd, client_message, MAX_REQUEST_SIZE-1, 0, (struct sockaddr *)&client_addr, &addr_len);
        // The main server sends requests in the format "deploy <username> <filenames>",
        // where <filenames> is a comma-separated string of filenames belonging to <username>
        std::string request_string(client_message);
        std::cout << "Server D has received a deploy request from the main server" << std::endl;
        std::vector<std::string> res = split(request_string, " ");
        std::string username = res[1];
        std::vector<std::string> filenames = split(res[2], ",");
        deploy(username, filenames);
        std::cout << "Server D has deployed the user " << username << "'s repository" << std::endl;
        sendto(udp_m_sock_fd, "deploy success", 14, 0, udp_m_serv_info->ai_addr, udp_m_serv_info->ai_addrlen);
    }
}