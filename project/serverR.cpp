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
        if (res.size() < 2) continue;
        line_count += 1;
        if (res[0] == username) {
            files += res[1] + ",";
        }
    }
    if (line_count == 0) return "repository 404";
    if (files.size() == 0) return "username 404";
    return files.substr(0, files.size()-1);
}

/**
 * Append a username and filename to filenames.txt
 */
void push_file(std::string filename, std::string username) {
    std::ofstream file("filenames.txt", std::ios_base::app | std::ios_base::out);
    file << username + " " + filename + "\n";
}

/**
 * Remove a username and filename from filenames.txt
 */
bool remove_file(std::string username, std::string filename) {
    std::vector<std::string> files;
    std::ifstream file("filenames.txt");
    std::string line;
    bool file_found = false;
    while (std::getline(file, line)) {
        std::vector<std::string> res = split(line, " ");
        if (res[0] == username && res[1] == filename) {
            file_found = true;
            continue;
        }
        files.push_back(line);
    }

    std::ofstream outfile("filenames.txt");
    for (std::string f : files) {
        outfile << f + "\n";
    }
    return file_found;
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
        std::cout << "Server R: getaddrinfo() failed" << std::endl;
        return 1;
    }
    if (getaddrinfo(nullptr, PORT_M_UDP, &hints, &udp_m_serv_info) != 0) {
        std::cout << "Server R: getaddrinfo() for connecting to server M failed" << std::endl;
        return 1;
    }

    sock_fd = bind_first(serv_info, false);
    // Make a UDP socket for server M
    struct addrinfo *m_addrinfo;
    for (m_addrinfo = udp_m_serv_info; m_addrinfo != nullptr; m_addrinfo = m_addrinfo->ai_next) {
        if ((udp_m_sock_fd = socket(m_addrinfo->ai_family, m_addrinfo->ai_socktype, m_addrinfo->ai_protocol)) == -1) {
            perror("Server R: socket() for UDP with M failed");
            continue;
        }
        break;
    }
    if (m_addrinfo == nullptr) {
        std::cout << "Server R: UDP socket() for server M failed" << std::endl;
        return 2;
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        perror("Server R: sigaction");
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
        if (
            request_string.rfind("lookup", 0) == 0
            || request_string.rfind("deploy", 0) == 0
        ) {
            bool is_lookup = request_string.rfind("lookup", 0) == 0;
            std::cout << "Server R has received a " << (is_lookup ? "lookup" : "deploy") << " request from the main server" << std::endl;
            std::vector<std::string> res = split(request_string, " ");
            std::string response = get_user_files(res[1]);
            strcpy(client_response, response.c_str());
            sendto(udp_m_sock_fd, client_response, MAX_RESPONSE_SIZE-1, 0, udp_m_serv_info->ai_addr, udp_m_serv_info->ai_addrlen);
            std::cout << "Server R has finished sending the response to the main server" << std::endl;
        }
        else if (request_string.rfind("push", 0) == 0) {
            std::vector<std::string> res = split(request_string, " ");
            std::vector<std::string> files = split(get_user_files(res[2]), ",");
            if (res[1] != "__confirm") {
                std::cout << "Server R has received a push request from the main server" << std::endl;
            }
            bool ask_confirmation = false;
            for (std::string file : files) {
                if (file == res[1]) {
                    // Ask for confirmation
                    ask_confirmation = true;
                    std::cout << file << " exists in " << res[2] << "'s repository; requesting overwrite confirmation" << std::endl;
                    char client_confirmation[MAX_REQUEST_SIZE] = "";
                    sendto(udp_m_sock_fd, "__confirm", 9, 0, udp_m_serv_info->ai_addr, udp_m_serv_info->ai_addrlen);
                    recvfrom(sock_fd, client_confirmation, MAX_REQUEST_SIZE-1, 0, (struct sockaddr *)&client_addr, &addr_len);
                    if (strcmp(client_confirmation, "push __confirm y") == 0) {
                        std::cout << "User requested overwrite; overwrite successful" << std::endl;
                        // We don't actually need to push again
                        // push_file(res[1], res[2]);

                        std::string overwrite_response = "push success " + file;
                        sendto(udp_m_sock_fd, overwrite_response.c_str(), strlen(overwrite_response.c_str()), 0, udp_m_serv_info->ai_addr, udp_m_serv_info->ai_addrlen);
                    }
                    else {
                        std::cout << "Overwrite denied" << std::endl;
                        sendto(udp_m_sock_fd, "push aborted", 12, 0, udp_m_serv_info->ai_addr, udp_m_serv_info->ai_addrlen);
                    }
                }
            }
            if (!ask_confirmation) {
                std::cout << res[1] << " uploaded successfully" << std::endl;
                push_file(res[1], res[2]);
                std::string push_response = "push success " + res[1];
                sendto(udp_m_sock_fd, push_response.c_str(), strlen(push_response.c_str()), 0, udp_m_serv_info->ai_addr, udp_m_serv_info->ai_addrlen);
            }
        }
        else if (request_string.rfind("remove", 0) == 0) {
            std::cout << "Server R has received a remove request from the main server" << std::endl;
            std::vector<std::string> res = split(request_string, " ");
            bool file_removed = remove_file(res[2], res[1]);
            sendto(udp_m_sock_fd, file_removed ? "remove success" : "remove 404", 14, 0, udp_m_serv_info->ai_addr, udp_m_serv_info->ai_addrlen);
        }

        if (request_string == "q") break;
    }
    close(sock_fd);
    return 0;
}