#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <csignal>
#include <string>
#include <cstring>
#include <fstream>

#include "utils.cpp"

// The number of clients server M will serve at a time
#define n_clients 10


/**
 * Log a request made by a user to logs.txt
 */
void log_request(std::string request) {
    std::ofstream log("logs.txt", std::ios_base::app | std::ios_base::out);
    log << request + "\n";
}

/**
 * Return a comma-separated string of the actions performed by the given username
 */
std::string get_logs(const std::string username) {
    std::ifstream log("logs.txt");
    std::string line;
    std::string history;
    while (std::getline(log, line)) {
        std::vector<std::string> res = split(line, " ");
        if (res[0] == "auth" && res[1] == username) history += line + ",";
        if (res[0] == "lookup" && res[2] == username) history += res[0] + " " + res[1] + ",";
        if (res[0] == "push" && res[2] == username) history += res[0] + " " + res[1] + ",";
        if (res[0] == "deploy" && res[1] == username) history += "deploy,";
        if (res[0] == "remove" && res[2] == username) history += res[0] + " " + res[1] + ",";
    }
    return history;
}


int main() {
    // Socket for incoming TCP connections from clients
    int client_sock_fd;
    // Child socket descriptor for handling TCP connections from clients
    int client_child_fd;
    // Socket for listening to incoming UDP connections from Server A, R, and D
    int udp_m_sock_fd;
    // Socket for sending data to server A over UDP
    int udp_a_sock_fd;
    // Socket for sending data to server R over UDP
    int udp_r_sock_fd;
    // Socket for sending data to server D over UDP
    int udp_d_sock_fd;
    // Store server M's connection info
    struct addrinfo *self_tcp_serv_info;
    struct addrinfo *self_udp_serv_info;
    // Store Server A's UDP connection info
    struct addrinfo *udp_a_serv_info;
    // Store Server R's UDP connection info
    struct addrinfo *udp_r_serv_info;
    // Store Server D's UDP connection info
    struct addrinfo *udp_d_serv_info;
    // Store the client's socket info
    struct sockaddr_storage client_addr;
    socklen_t sin_size;

    // Handle quitting
    // Taken from Beej’s Guide to Network Programming (v3.1.12), section 6.1
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        perror("Server M: sigaction");
        exit(1);
    }

    struct addrinfo client_hints = get_hints(true);
    struct addrinfo udp_hints = get_hints(false);

    // Taken from Beej’s Guide to Network Programming (v3.1.12), section 6.1
    if (getaddrinfo(nullptr, PORT_M_TCP, &client_hints, &self_tcp_serv_info) != 0) {
        std::cout << "Server M: getaddrinfo() for TCP failed" << std::endl;
        return 1;
    }
    if (getaddrinfo(nullptr, PORT_M_UDP, &udp_hints, &self_udp_serv_info) != 0) {
        std::cout << "Server M: getaddrinfo() for UDP failed" << std::endl;
        return 1;
    }
    if (getaddrinfo(nullptr, PORT_A, &udp_hints, &udp_a_serv_info) != 0) {
        std::cout << "Server M: getaddrinfo() for UDP failed" << std::endl;
        return 1;
    }
    if (getaddrinfo(nullptr, PORT_R, &udp_hints, &udp_r_serv_info) != 0) {
        std::cout << "Server M: getaddrinfo() for UDP failed" << std::endl;
        return 1;
    }
    if (getaddrinfo(nullptr, PORT_D, &udp_hints, &udp_d_serv_info) != 0) {
        std::cout << "Server M: getaddrinfo() for UDP failed" << std::endl;
        return 1;
    }

    // Make a TCP socket for self
    client_sock_fd = bind_first(self_tcp_serv_info);
    if (listen(client_sock_fd, n_clients) == -1) {
        perror("Server M: listen() failed");
        exit(1);
    }

    // Taken from Beej’s Guide to Network Programming (v3.1.12), section 6.3
    // Make a UDP socket for self
    udp_m_sock_fd = bind_first(self_udp_serv_info, false);
    std::cout << "Server M is up and running using UDP on port " << PORT_M_UDP << "." << std::endl;

    // Taken from Beej’s Guide to Network Programming (v3.1.12), section 6.3
    // Make a UDP socket for server A
    struct addrinfo *a_addrinfo;
    for (a_addrinfo = udp_a_serv_info; a_addrinfo != nullptr; a_addrinfo = a_addrinfo->ai_next) {
        if ((udp_a_sock_fd = socket(a_addrinfo->ai_family, a_addrinfo->ai_socktype, a_addrinfo->ai_protocol)) == -1) {
            perror("Server M: socket() for UDP with A failed");
            continue;
        }
        break;
    }
    if (a_addrinfo == nullptr) {
        std::cout << "Server M: UDP socket() for server A failed" << std::endl;
        return 2;
    }
    // Make a UDP socket for server R
    struct addrinfo *r_addrinfo;
    for (r_addrinfo = udp_r_serv_info; r_addrinfo != nullptr; r_addrinfo = r_addrinfo->ai_next) {
        if ((udp_r_sock_fd = socket(r_addrinfo->ai_family, r_addrinfo->ai_socktype, r_addrinfo->ai_protocol)) == -1) {
            perror("Server M: socket() for UDP with R failed");
            continue;
        }
        break;
    }
    if (r_addrinfo == nullptr) {
        std::cout << "Server M: UDP socket() for server R failed" << std::endl;
        return 2;
    }
    // Make a UDP socket for server D
    struct addrinfo *d_addrinfo;
    for (d_addrinfo = udp_d_serv_info; d_addrinfo != nullptr; d_addrinfo = d_addrinfo->ai_next) {
        if ((udp_d_sock_fd = socket(d_addrinfo->ai_family, d_addrinfo->ai_socktype, d_addrinfo->ai_protocol)) == -1) {
            perror("Server M: socket() for UDP with D failed");
            continue;
        }
        break;
    }
    if (d_addrinfo == nullptr) {
        std::cout << "Server M: UDP socket() for server D failed" << std::endl;
        return 2;
    }


    while (1) {
        sin_size = sizeof client_addr;
        client_child_fd = accept(client_sock_fd, (struct sockaddr *)&client_addr, &sin_size);
        if (client_child_fd == -1) {
            perror("Server M: accept() failed");
            continue;
        }

        // This is the child process
        if (!fork()) {
            char client_message[MAX_REQUEST_SIZE] = "";
            // Child doesn't need the parent socket
            close(client_sock_fd);
            recv(client_child_fd, client_message, MAX_REQUEST_SIZE - 1, 0);
            std::string request(client_message);
            if (request.rfind("auth", 0) == 0) {
                // Auth request from client has format "auth <username> <password>"
                std::vector<std::string> res = split(request, " ");
                std::cout << "Server M has received username " << res[1] << " and password ******" << std::endl;
                char auth_response[MAX_RESPONSE_SIZE] = "";
                struct sockaddr_storage a_addr;
                socklen_t a_addr_len = sizeof a_addr;

                sendto(udp_a_sock_fd, client_message, strlen(client_message), 0, a_addrinfo->ai_addr, a_addrinfo->ai_addrlen);
                std::cout << "Server M has sent authentication request to Server A" << std::endl;
                recvfrom(udp_m_sock_fd, auth_response, MAX_RESPONSE_SIZE-1, 0, (struct sockaddr *)&a_addr, &a_addr_len);
                std::cout << "The main server has received the response from server A using UDP over " << PORT_M_UDP << std::endl;

                char client_response[MAX_RESPONSE_SIZE] = "";
                strcpy(client_response, auth_response);
                send(client_child_fd, client_response, MAX_RESPONSE_SIZE, 0);
                std::cout << "The main server has sent the response from server A to client using TCP over port " << PORT_M_TCP << std::endl;
            }
            else if (request.rfind("lookup", 0) == 0) {
                char lookup_response[MAX_RESPONSE_SIZE] = "";
                struct sockaddr_storage r_addr;
                socklen_t r_addr_len = sizeof r_addr;
                // Lookup request from client has format "lookup <username> <authenticated_username>"
                // authenticated_username can be a username if the user is authenticated, or "guest"
                std::vector<std::string> res = split(request, " ");
                // The username to lookup
                const std::string username = res[1];
                // The username of the user doing the lookup (or "guest")
                const std::string auth_username = res[2];
                if (auth_username == "guest") {
                    std::cout << "The main server has received a lookup request from Guest to lookup " << username << "'s repository using TCP over port " << PORT_M_TCP << std::endl;
                }
                else {
                    std::cout << "The main server has received a lookup request from " << auth_username << " to lookup " << username << "'s repository using TCP over port " << PORT_M_TCP << std::endl;
                }
                sendto(udp_r_sock_fd, client_message, strlen(client_message), 0, r_addrinfo->ai_addr, r_addrinfo->ai_addrlen);
                std::cout << "The main server has sent the lookup request to server R" << std::endl;
                recvfrom(udp_m_sock_fd, lookup_response, MAX_RESPONSE_SIZE-1, 0, (struct sockaddr *)&r_addr, &r_addr_len);
                std::cout << "The main server has received the response from server R using UDP over " << PORT_M_UDP << std::endl;

                char client_response[MAX_RESPONSE_SIZE] = "";
                strcpy(client_response, lookup_response);
                send(client_child_fd, client_response, MAX_RESPONSE_SIZE, 0);
                std::cout << "The main server has sent the response to the client" << std::endl;
            }
            else if (request.rfind("push", 0) == 0) {
                char push_response[MAX_RESPONSE_SIZE] = "";
                struct sockaddr_storage r_addr;
                socklen_t r_addr_len = sizeof r_addr;
                // Push request from client has format "push <filename> <authenticated_username>"
                // OR a confirmation of the format "push __confirm y|n"
                std::vector<std::string> res = split(request, " ");
                const std::string username = res[2];
                const std::string filename = res[1];
                if (res[1] != "__confirm") {
                    // Sending a push request for the first time
                    std::cout << "The main server has received a push request from " << username << ", using TCP over port " << PORT_M_TCP << std::endl;
                }
                else {
                    // Sending a push confirmation
                    std::cout << "The main server has received the overwrite confirmation response from " << username << " using TCP over port " << PORT_M_TCP << std::endl;
                }
                sendto(udp_r_sock_fd, client_message, strlen(client_message), 0, r_addrinfo->ai_addr, r_addrinfo->ai_addrlen);
                if (res[1] != "__confirm") std::cout << "The main server has sent the push request to server R" << std::endl;
                else std::cout << "The main server has sent the overwrite confirmation response to server R" << std::endl;
                recvfrom(udp_m_sock_fd, push_response, MAX_RESPONSE_SIZE-1, 0, (struct sockaddr *)&r_addr, &r_addr_len);
                if (strcmp(push_response, "__confirm") != 0) {
                    // Push succeeded (no confirmation was needed or confirmation successfully received)
                    std::cout << "The main server has received the response from server R using UDP over " << PORT_M_UDP << std::endl;
                    send(client_child_fd, push_response, MAX_RESPONSE_SIZE, 0);
                    std::cout << "The main server has sent the response to the client" << std::endl;
                }
                else {
                    // Server R is asking for confirmation
                    std::cout << "The main server has received the response from server R using UDP over " << PORT_M_UDP << ", asking for overwrite confirmation" << std::endl;
                    send(client_child_fd, push_response, MAX_RESPONSE_SIZE, 0);
                    std::cout << "The main server has sent the overwrite confirmation request to the client" << std::endl;
                    char push_request_confirmation[MAX_REQUEST_SIZE] = "";
                    recv(client_child_fd, push_request_confirmation, MAX_REQUEST_SIZE-1, 0);
                    std::cout << "The main server has received the overwrite confirmation response from " << username << " using TCP over port " << PORT_M_TCP << std::endl;
                    sendto(udp_r_sock_fd, push_request_confirmation, strlen(push_request_confirmation), 0, r_addrinfo->ai_addr, r_addrinfo->ai_addrlen);
                    std::cout << "The main server has sent the overwrite confirmation response to server R" << std::endl;
                    strcpy(push_response, "");
                    recvfrom(udp_m_sock_fd, push_response, MAX_RESPONSE_SIZE-1, 0, (struct sockaddr *)&r_addr, &r_addr_len);
                    std::cout << "The main server has received the response from server R using UDP over " << PORT_M_UDP << std::endl;
                    send(client_child_fd, push_response, MAX_RESPONSE_SIZE, 0);
                    std::cout << "The main server has sent the response to the client" << std::endl;
                }
            }
            else if (request.rfind("deploy", 0) == 0) {
                char deploy_response[MAX_RESPONSE_SIZE] = "";
                char lookup_response[MAX_RESPONSE_SIZE] = "";
                struct sockaddr_storage r_addr;
                socklen_t r_addr_len = sizeof r_addr;
                struct sockaddr_storage d_addr;
                socklen_t d_addr_len = sizeof d_addr;
                // Deploy request from client has format "deploy <authenticated_username>"
                std::vector<std::string> res = split(request, " ");
                const std::string username = res[1];
                const std::string auth_username = res[1];
                std::cout << "The main server has received a deploy request from member " << username << " using TCP over port " << PORT_M_TCP << std::endl;
                const std::string lookup_request = "lookup " + username + " " + auth_username;
                sendto(udp_r_sock_fd, lookup_request.c_str(), strlen(lookup_request.c_str()), 0, r_addrinfo->ai_addr, r_addrinfo->ai_addrlen);
                std::cout << "The main server has sent the lookup request to server R" << std::endl;
                recvfrom(udp_m_sock_fd, lookup_response, MAX_RESPONSE_SIZE-1, 0, (struct sockaddr *)&r_addr, &r_addr_len);
                std::cout << "The main server received the lookup response from server R" << std::endl;
                std::string deploy_request(lookup_response);
                deploy_request = "deploy " + username + " " + deploy_request;
                sendto(udp_d_sock_fd, deploy_request.c_str(), strlen(deploy_request.c_str()), 0, d_addrinfo->ai_addr, d_addrinfo->ai_addrlen);
                std::cout << "The main server has sent the deploy request to server D" << std::endl;
                recvfrom(udp_m_sock_fd, deploy_response, MAX_RESPONSE_SIZE-1, 0, (struct sockaddr *)&d_addr, &d_addr_len);
                std::cout << "The user " << username << "'s repository has been deployed at server D" << std::endl;
                send(client_child_fd, lookup_response, MAX_RESPONSE_SIZE, 0);
            }
            else if (request.rfind("remove", 0) == 0) {
                char remove_response[MAX_RESPONSE_SIZE] = "";
                struct sockaddr_storage r_addr;
                socklen_t r_addr_len = sizeof r_addr;
                // Remove request from client has format "remove <filename> <authenticated_username>"
                std::vector<std::string> res = split(request, " ");
                std::cout << "The main server has received a remove request from member " << res[2] << " using TCP over port " << PORT_M_TCP << std::endl;
                sendto(udp_r_sock_fd, client_message, strlen(client_message), 0, r_addrinfo->ai_addr, r_addrinfo->ai_addrlen);
                recvfrom(udp_m_sock_fd, remove_response, MAX_RESPONSE_SIZE-1, 0, (struct sockaddr *)&r_addr, &r_addr_len);
                std::cout << "The main server has received confirmation of the remove request done by server R" << std::endl;
                send(client_child_fd, remove_response, MAX_RESPONSE_SIZE, 0);
            }
            else if (request.rfind("log", 0) == 0) {
                // Log request from client has format "log <username>"
                std::vector<std::string> res = split(request, " ");
                std::string logs = get_logs(res[1]);
                send(client_child_fd, logs.c_str(), MAX_RESPONSE_SIZE, 0);
            }
            log_request(request);
            exit(0);
        }
         // Parent doesn't need the child socket
        close(client_child_fd);
    }
}