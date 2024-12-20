#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <fstream>

#include "utils.cpp"


enum class client_state {
    AUTH,
    LOOKUP,
    PUSH,
    DEPLOY,
    REMOVE,
    LOG,
    UNSPECIFIED
};

int SELF_PORT = 0;

auth_type authenticate(std::string username, std::string password, int sock_fd) {
    std::string auth_request_string = "auth " + username + " " + encrypt_password(password);
    char auth_request[auth_request_string.length()+1];
    char auth_response[MAX_RESPONSE_SIZE];
    strcpy(auth_request, auth_request_string.c_str());

    send(sock_fd, auth_request, strlen(auth_request), 0);
    recv(sock_fd, auth_response, MAX_RESPONSE_SIZE, 0);

    if (strcmp(auth_response, "success") == 0) {
        std::cout << "You have been granted member access" << std::endl;
        return auth_type::MEMBER;
    }
    else if (strcmp(auth_response, "auth guest") == 0) {
        std::cout << "You have been granted guest access" << std::endl;
        return auth_type::GUEST;
    }
    else if (strcmp(auth_response, "auth failed") == 0) {
        std::cout << "The credentials are incorrect. Please try again." << std::endl;
        return auth_type::ANONYMOUS;
    }
    return auth_type::ANONYMOUS;
}


/**
 * Preprocesses the user's command to add required metadata
 * before sending the request to server M
 */
std::string process_request(
        std::string command,
        bool is_authenticated,
        bool is_guest,
        std::string username,
        client_state state
    ) {
    // Add the username of the member doing the lookup. Required
    // by server M to print who sent the lookup request.
    if (command.rfind("lookup", 0) == 0) {
        std::vector<std::string> res = split(command, " ");
        if (res.size() == 1) {
            command += " " + username;
            std::cout << "Username is not specified. Will lookup " << username << std::endl;
        }
        if (is_authenticated) command += " " + username;
        else if (is_guest) command += " guest";
        std::cout << username << " sent a lookup request to the main server" << std::endl;
        return command;
    }
    // Add the username of the member pushing, required by server R to determine
    // which repository to push to
    if (command.rfind("push", 0) == 0) {
        return command + " " + username;
    }
    // Add a confirmation parameter if the user is pushing and server R
    // requested confirmation to overwrite
    if (
        (state == client_state::PUSH && lower(command).rfind("y", 0) == 0)
        || (state == client_state::PUSH && lower(command).rfind("n", 0) == 0)
    ) {
        return "push __confirm " + lower(command);
    }
    // Add the username of the member deploying
    if (command.rfind("deploy", 0) == 0) {
        return command + " " + username;
    }
    // Add the username of the member removing a file
    if (command.rfind("remove", 0) == 0) {
        std::cout << username << " sent a remove request to the main server" << std::endl;
        return command + " " + username;
    }
    // Add the username of the member requesting logs
    if (command.rfind("log", 0) == 0) {
        std::cout << username << " sent a log request to the main server" << std::endl;
        return command + " " + username;
    }
    return command;
}

/**
 * Validate the user's request before sending it to server M
 */
bool validate_request(std::string request, bool is_authenticated, bool is_guest) {
    if (request.rfind("lookup", 0) == 0) {
        std::vector<std::string> res = split(request, " ");
        if (is_guest && res[1] == "guest") {
            std::cout << "Error: username is required. Please specify a username to lookup" << std::endl;
            return false;
        }
        return res.size() == 3;
    }
    if (request.rfind("push", 0) == 0) {
        // Guests can't push
        if (is_guest) {
            std::cout << "Error: you need to be authenticated to run the push command" << std::endl;
            return false;
        }
        std::vector<std::string> res = split(request, " ");
        if (res.size() == 2) {
            std::cout << "Error: filename is required. Please specify a filename to push." << std::endl;
            return false;
        }
        if (res.size() == 3 && res[2] == "guest") return false;
        std::ifstream file(res[1]);
        if (!file.good()) {
            std::cout << "Error: invalid file: " << res[1] << std::endl;
            std::cout << "—--Start a new request—--" << std::endl;
            return false;
        }
        file.close();
        return res.size() == 3;
    }
    if (request.rfind("remove", 0) == 0) {
        // Guests can't remove
        if (is_guest) {
            std::cout << "Error: you need to be authenticated to run the remove command" << std::endl;
            return false;
        }
        std::vector<std::string> res = split(request, " ");
        if (res.size() < 3) {
            std::cout << "Error: filename is required" << std::endl;
            return false;
        }
        if (res.size() > 3) {
            std::cout << "Error: filename cannot contain spaces" << std::endl;
            return false;
        }
        return res.size() == 3;
    }
    if (request.rfind("log", 0) == 0) {
        if (is_guest) {
            std::cout << "Error: you need to be authenticated to run the log command" << std::endl;
            return false;
        }
    }
    if (request.rfind("deploy", 0) == 0) {
        if (is_guest) {
            std::cout << "Error: you need to be authenticated to run the deploy command" << std::endl;
            return false;
        }
    }
    return true;
}

/**
 * Perform any actions required after receiving response from server M
 */
std::string process_response(std::string request, std::string response, client_state state) {
    if (state == client_state::LOOKUP) {
        std::cout << "The client received the response from the main server using TCP over port " << SELF_PORT << std::endl;
        if (response == "username 404") {
            std::cout << split(request, " ")[1] << " does not exist. Please try again." << std::endl;
            std::cout << "—--Start a new request—--" << std::endl;
            return response;
        }
        if (response == "repository 404") {
            std::cout << "Empty repository." << std::endl;
            std::cout << "—--Start a new request—--" << std::endl;
            return response;
        }
        std::vector<std::string> res = split(response, ",");
        std::string result = "";
        for (std::string file : res) {
            result += file + "\n";
        }
        std::cout << result << std::endl;
        std::cout << "—--Start a new request—--" << std::endl;
        return result;
    }
    if (state == client_state::PUSH) {
        std::vector<std::string> res = split(request, " ");
        std::string filename = res[1];
        std::string username = res[2];
        if (response.rfind("push success", 0) == 0) std::cout << split(response, " ")[2] << " pushed successfully" << std::endl;
        else if (response == "push abort") std::cout << filename << " was not pushed successfully" << std::endl;
        else if (response == "__confirm") std::cout << filename << " exists in " << username << "'s repository, do you want to overwrite (y/n)?" << std::endl;
    }
    if (state == client_state::DEPLOY) {
        std::cout << "The client received the response from the main server using TCP over port " << SELF_PORT << ". The following files in his/her repository have been deployed" << std::endl;
        std::vector<std::string> res = split(response, ",");
        std::string result = "";
        for (std::string file : res) {
            result += file + "\n";
        }
        std::cout << result << std::endl;
        std::cout << "—--Start a new request—--" << std::endl;
        return response;
    }
    if (state == client_state::REMOVE) {
        if (response == "remove success") std::cout << "The remove request was successful" << std::endl;
        else if (response == "remove 404") std::cout << "The specified file does not exist" << std::endl;
    }
    if (state == client_state::LOG) {
        std::vector<std::string> res = split(response, ",");
        std::cout << "The client received the response from the main server using TCP over port " << SELF_PORT << std::endl;
        for (int i = 0; i < (int) res.size(); i++) {
            if (res[i] == "") continue;
            std::cout << i << ". " << res[i] << std::endl;
        }
        std::cout << "—--Start a new request—--" << std::endl;
    }
    return response;
}

/**
 * Set the current state of the client. If the user enters an unknown
 * command, return the previous state
 */
client_state set_client_state(std::string request, client_state prev_state) {
    if (request.rfind("lookup", 0) == 0) return client_state::LOOKUP;
    if (request.rfind("push", 0) == 0) return client_state::PUSH;
    if (request.rfind("deploy", 0) == 0) return client_state::DEPLOY;
    if (request.rfind("remove", 0) == 0) return client_state::REMOVE;
    if (request.rfind("log", 0) == 0) return client_state::LOG;
    return prev_state;
}


int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cout << "Provide the client username and password for authentication:" << std::endl << "./client <username> <password>" << std::endl;
        exit(1);
    }
    std::cout << "The client is up and running." << std::endl;
    std::string username(argv[1]);
    std::string password(argv[2]);
    client_state state = client_state::AUTH;


    int sock_fd;
    // Store the server's TCP connection info
    struct addrinfo *serv_info;
    // Store the client's socket info
    sockaddr_in local_addr;
    // Store true if the client is authenticated as a member
    bool is_authenticated = false;
    bool is_guest = false;

    while (1) {
        char response[MAX_RESPONSE_SIZE] = "";
        char request[MAX_REQUEST_SIZE]  = "";
        // Taken from Beej’s Guide to Network Programming (v3.1.12), section 6.1
        struct addrinfo hints = get_hints(true);
        if ((getaddrinfo(nullptr, PORT_M_TCP, &hints, &serv_info)) != 0) {
            std::cout << "Client: getaddrinfo() failed" << std::endl;
            return 1;
        }

        sock_fd = connect_first(serv_info);
        freeaddrinfo(serv_info);
        // Get client port number
        socklen_t addrlen = sizeof(local_addr);
        getsockname(sock_fd, (sockaddr*)&local_addr, &addrlen);
        SELF_PORT = ntohs(local_addr.sin_port);

        if (!is_authenticated && !is_guest) {
            auth_type auth = authenticate(argv[1], argv[2], sock_fd);
            if (auth == auth_type::MEMBER) {
                is_authenticated = true;
                is_guest = false;
            }
            else if (auth == auth_type::GUEST) {
                is_authenticated = false;
                is_guest = true;
            }
            else {
                is_authenticated = false;
                is_guest = false;
                exit(1);
            }
            continue;
        }

        strcpy(request, "");
        std::cin.getline(request, MAX_REQUEST_SIZE);
        std::string request_string(request);
        state = set_client_state(request, state);

        // Preprocess request
        request_string = process_request(request_string, is_authenticated, is_guest, username, state);
        if (!validate_request(request_string, is_authenticated, is_guest)) {
            std::cout << "Please enter the command:\n<lookup <username>>\n<push <filename>>\n<remove <filename>>\n<deploy>\n<log>" << std::endl;
            continue;
        }

        strcpy(request, request_string.c_str());

        send(sock_fd, request, strlen(request), 0);
        recv(sock_fd, response, MAX_RESPONSE_SIZE, 0);
        std::string response_string(response);
        process_response(request_string, response_string, state);
    }
}