/**
* Utility functions used in multiple places
*/
#include <algorithm>
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <vector>

// Hardcoded server ports
#define PORT_A "21261"
#define PORT_R "22261"
#define PORT_D "23261"
#define PORT_M_UDP "24261"
#define PORT_M_TCP "25261"

// The maximum expected response size in bytes
#define MAX_RESPONSE_SIZE 1000
#define MAX_REQUEST_SIZE 200

enum class auth_type {
    ANONYMOUS,
    GUEST,
    MEMBER
};


void sigchld_handler(int s) {
    int saved_errno = errno;
    while (waitpid(-1, nullptr, WNOHANG) > 0);
    errno = saved_errno;
}


/**
 * Get sockaddr, IPv4 or IPv6
 */
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/**
 * Get the hints struct to pass to getaddrinfo()
 */
struct addrinfo get_hints(bool stream_socket = true) {
    struct addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = stream_socket ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    return hints;
}

/**
 * Given an addrinfo struct obtained from getaddrinfo(), bind to the
 * first socket available
 */
int bind_first(struct addrinfo *serv_info, bool stream_socket = true) {
    struct addrinfo *p;
    int sock_fd = -1;
    int yes = 1;

    for (p = serv_info; p != nullptr; p = p->ai_next) {
        if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("Server: socket() failed");
            continue;
        }

        if (stream_socket && setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("Server: setsockopt() failed");
            exit(1);
        }

        if (bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock_fd);
            perror("Server: bind() failed");
            continue;
        }
        break;
    }
    if (p == nullptr) {
        std::cout << "Server: bind() failed" << std::endl;
        exit(1);
    }

    freeaddrinfo(serv_info);
    return sock_fd;
}


int connect_first(struct addrinfo *serv_info) {
    struct addrinfo *p;
    int sock_fd = -1;
    for (p = serv_info; p != nullptr; p = p->ai_next) {
        if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("Client: socket() failed");
            continue;
        }

        if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock_fd);
            perror("Client: connect() failed");
            continue;
        }
        break;
    }
    if (p == nullptr) {
        std::cout << "Client: connect() failed" << std::endl;
    }
    return sock_fd;
}

/**
 * Encrypt a plaintext password
 */
std::string encrypt_password(const std::string &password) {
    std::string result = password;
    for (char &c : result) {
        if (c >= 'A' && c <= 'Z') c = ((c - 'A' + 3) % 26) + 'A';
        else if (c >= 'a' && c <= 'z') c = ((c - 'a' + 3) % 26) + 'a';
        else if (c >= '0' && c <= '9') c = ((c - '0' + 3) % 10) + '0';
    }
    return result;
}

/**
 * Decrypt and encrypted password
 */
std::string decrypt_password(const std::string &password) {
    std::string result = password;
    for (char &c : result) {
        if (c >= 'A' && c <= 'Z') c = ((c - 'A' - 3 + 26) % 26) + 'A';
        else if (c >= 'a' && c <= 'z') c = ((c - 'a' - 3 + 26) % 26) + 'a';
        else if (c >= '0' && c <= '9') c = ((c - '0' - 3 + 10) % 10) + '0';
    }
    return result;
}

/**
 * Split string s by delimiter
 */
std::vector<std::string> split(std::string s, std::string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
        token = s.substr(pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back(token);
    }

    res.push_back (s.substr(pos_start));
    return res;
}


char _lower(char in) {
    if (in <= 'Z' && in >= 'A')
        return in - ('Z' - 'z');
    return in;
}

/**
 * Convert a string to lowercase
 */
std::string lower(std::string a) {
    std::transform(a.begin(), a.end(), a.begin(), _lower);
    return a;
}