#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <csignal>
#include <string>
#include <cstring>

#include "utils.cpp"

// The number of clients server M will serve at a time
#define n_clients 10


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
    // Store server M's connection info
    struct addrinfo *self_tcp_serv_info;
    struct addrinfo *self_udp_serv_info;
    // Store Server A's UDP connection info
    struct addrinfo *udp_a_serv_info;
    // Store Server R's UDP connection info
    struct addrinfo *udp_r_serv_info;
    // Store the client's socket info
    struct sockaddr_storage client_addr;
    socklen_t sin_size;

    // Handle quitting
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

    // Make a TCP socket for self
    client_sock_fd = bind_first(self_tcp_serv_info);
    if (listen(client_sock_fd, n_clients) == -1) {
        perror("Server M: listen() failed");
        exit(1);
    }

    // Make a UDP socket for self
    udp_m_sock_fd = bind_first(self_udp_serv_info, false);
    std::cout << "Server M is up and running using UDP on port " << PORT_M_UDP << "." << std::endl;

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
            std::cout << "----Received request from client: " << request << std::endl;
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

            }
            else if (request.rfind("deploy", 0) == 0) {

            }
            else if (request.rfind("remove", 0) == 0) {

            }
            else if (request.rfind("log", 0) == 0) {

            }
            else {
                // Otherwise just echo
                std::cout << "----Echoing request " << client_message << std::endl;
                send(client_child_fd, client_message, MAX_RESPONSE_SIZE, 0);
            }
//            close(client_child_fd);
            exit(0);
        }
         // Parent doesn't need the child socket
        close(client_child_fd);
    }
}