# EE 450 Project

|            |                       |
|------------|-----------------------|
| Name       | Hrushikesh Vaidya     |
| Student ID | 3486205261            |
| Session    | Session 2 (Afternoon) |

## Project Description
This project implements a simplified version control system called Git450. It implements 
simple user authentication, repository management (with the assumption that each user 
has only one repository), and deployment execution.

**I have also implemented the extra credit `log` command**

It supports the following commands -

1. Authentication - Authenticates a user against a username and password
2. Lookup - Prints a list of files in a particular user's repository
3. Push - Pushes a file in a user's repository
4. Deploy - Deploys a particular user's repository
5. Remove - Removes a pushed file from a user's repository
6. Log - Prints a list of the commands executed by a particular user

All commands are completely functional with no errors, and handle the expected workflow correctly.

## Code Files
This project contains the following files -

| File        | Description                                                                                                                                                                                                      |
|-------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| client.cpp  | Allows users to connect to the system via server M. Connects to server M via TCP and exchanges commands and responses                                                                                            |
| serverM.cpp | Manages TCP connections from clients and UDP connections with backend servers A, R, and D, and is responsible for establishing communication between the frontend (client) and the backend (servers A, R, and D) |
| serverA.cpp | Manages user authentication. Receives authentication requests containing user credentials from server M and sends success or failure responses                                                                   |
| serverR.cpp | Manages user repositories. Maintains the list of files owned by all members and is responsible for handling the lookup, push, and remove commands                                                                |
| serverD.cpp | Manages repository deployments. Maintains the list of deployed files by all members and is responsible for handling the deploy command                                                                           |
| utils.cpp   | A utility file that contains common utility functions required by multiple files                                                                                                                                 |

The project also contains a `Makefile` that builds the required executables for the project. I have tried to include as many comments as possible
to explain what each function defined in each file does, as well as general comments in the `main()` functions of each file.

## Message Format
I have used a plaintext format for exchanging messages between the servers and clients with
no specialized serialization/deserialization.

### Client Messages
The client accepts input from the user and looks for the commands listed below. If the user input
matches a valid command, the client preprocesses the user's input to add some metadata to the input
before sending it as a command to server M. All messages are sent as plain strings and no specialized
serialization or deserialization format (e.g. JSON) is used. In the table below I have listed the
strings sent by the client to server M after preprocessing.

| Command        | Message Format                               | Explanation                                                                                                                                                                                                                                    |
|----------------|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Authentication | `auth <username> <password>`                 | `<username>` and `<password>` is the username and password entered by the user while starting the client                                                                                                                                       |
| Lookup         | `lookup <username> <authenticated_username>` | The client adds `<authenticated_username>` during preprocessing, which is the username of the currently authenticated user. If the user does not specify the username in the command, it also adds the current user's username as `<username>` |
| Push           | `push <filename> <authenticated_username>`   | The client adds `<authenticated_username>` during preprocessing, which is the username of the currently authenticated user. This is used by server R to know which user's repository to push to                                                |
| Deploy         | `deploy <authenticated_username>`            | The client adds `<authenticated_username>` during preprocessing, which is the username of the currently authenticated user. This is used by server R and D to know which user's repository to deploy                                           |
| Remove         | `remove <filename> <authenticated_username>` | The client adds `<authenticated_username>` during preprocessing, which is the username of the currently authenticated user. This is used by server R to know which user's file to remove                                                       |
| Log            | `log <authenticated_username>`               | The client adds `<authenticated_username>` during preprocessing, which is the username of the currently authenticated user. This is used by server M to know which user's logs to display                                                      |

## Idiosyncrasies
The project has no idiosyncrasies. It works correctly for all commands and under all testing conditions. It also works correctly
with concurrent connections. 

## Reused Code
I have referred to Beej’s Guide to Network Programming (v3.1.12) during this project and used a few code snippets from
it. Specifically, I have used code from sections `6.1`, `6.2`, and `6.3` which show how to call `getaddrinfo()`, 
`socket()`, `bind()`, `listen()`, etc. I have marked the used code  with comments.