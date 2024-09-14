// sender.cpp
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

#pragma comment(lib, "Ws2_32.lib")

struct MessageInfo {
    int index;
    std::string messageSent;
    int messageReceived;
    bool completed;
};

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    int wsaInit = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaInit != 0) {
        std::cerr << "WSAStartup failed with error: " << wsaInit << std::endl;
        return 1;
    }

    // Create a socket to connect to the server
    SOCKET connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connectSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed with error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Set up the server address structure
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(55000);  // Server port
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Server IP address (loopback)

    // Connect to the server
    if (connect(connectSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connect failed with error: " << WSAGetLastError() << std::endl;
        closesocket(connectSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Connected to server at 127.0.0.1:55000" << std::endl;

    // Read messages from file
    std::ifstream file("messagesFile.txt");  // Open the file for reading
    if (!file.is_open()) {
        std::cerr << "Failed to open file 'messagesFile.txt'." << std::endl;
        closesocket(connectSocket);
        WSACleanup();
        return 1;
    }

    std::vector<MessageInfo> messageInfoVector;
    std::string line;
    int index = 0;

    // Read each line from the file
    while (std::getline(file, line)) {
        // Include the id (index) into the message
        std::stringstream ss;
        ss << index << ":" << line;

        MessageInfo info;
        info.index = index;
        info.messageSent = ss.str();
        info.completed = false;
        info.messageReceived = -1;
        messageInfoVector.push_back(info);

        index++;
    }

    file.close();  // Close the file

    // Send messages to the server and receive responses
    for (size_t i = 0; i < messageInfoVector.size(); ++i) {
        // Send the message to the server
        std::string& messageToSend = messageInfoVector[i].messageSent;
        int sendResult = send(connectSocket, messageToSend.c_str(), messageToSend.length(), 0);
        if (sendResult == SOCKET_ERROR) {
            std::cerr << "Send failed with error: " << WSAGetLastError() << std::endl;
            break;
        }
        std::cout << "Message sent: " << messageToSend << std::endl;

        // Receive response from the server
        char recvbuf[512];
        int recvbuflen = sizeof(recvbuf);

        int recvResult = recv(connectSocket, recvbuf, recvbuflen, 0);
        if (recvResult > 0) {
            std::string receivedData(recvbuf, recvResult);
            std::cout << "Response received: " << receivedData << std::endl;

            // Parse the received response
            size_t delimiter_pos = receivedData.find(':');
            if (delimiter_pos != std::string::npos) {
                int id = std::stoi(receivedData.substr(0, delimiter_pos));
                int message = std::stoi(receivedData.substr(delimiter_pos + 1));

                // Update the message info
                messageInfoVector[id].messageReceived = message;
                messageInfoVector[id].completed = true;
            }
        } else if (recvResult == 0) {
            std::cout << "Connection closed by server." << std::endl;
            break;
        } else {
            std::cerr << "Receive failed with error: " << WSAGetLastError() << std::endl;
            break;
        }

        // Optional: Wait before sending the next message
        // Sleep(1000);  // Sleep for 1 second
    }

    // Close the socket
    closesocket(connectSocket);
    WSACleanup();

    // Print out the results
    std::cout << "\nAll messages processed:" << std::endl;
    for (const auto& info : messageInfoVector) {
        std::cout << "Initial num: " << info.messageSent
                  << ", Output: " << info.messageReceived << std::endl;
    }

    return 0;
}
