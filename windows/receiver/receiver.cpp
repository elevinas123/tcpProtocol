// receiver.cpp
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <sstream>

#pragma comment(lib, "Ws2_32.lib")

// Structure to hold parsed received messages
struct ParsedReceivedMessage {
    std::string id;
    int message;
};

// Function to parse the payload into a struct
ParsedReceivedMessage parseReceivedPayloadToStruct(const std::string& payload) {
    ParsedReceivedMessage parsed;
    size_t delimiter_pos = payload.find(':');
    if (delimiter_pos != std::string::npos) {
        parsed.id = payload.substr(0, delimiter_pos);
        std::string message_str = payload.substr(delimiter_pos + 1);
        parsed.message = std::stoi(message_str);
    } else {
        std::cerr << "Invalid payload format: " << payload << std::endl;
        parsed.id = "";
        parsed.message = 0;
    }
    return parsed;
}

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    int wsaInit = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaInit != 0) {
        std::cerr << "WSAStartup failed with error: " << wsaInit << std::endl;
        return 1;
    }

    // Create a listening socket
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed with error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Bind the socket to the specific IP address and port
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(55000);  // Use port 55000
    serverAddr.sin_addr.s_addr = inet_addr("192.168.1.180");  // Bind to specific IP address

    if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed with error: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    // Listen for incoming connection requests
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed with error: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server is listening on 192.168.1.180:55000..." << std::endl;

    while (true) {
        // Accept a client socket
        SOCKET clientSocket;
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);

        clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed with error: " << WSAGetLastError() << std::endl;
            continue;  // Continue to accept other connections
        }

        // Retrieve and display client's IP address
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        std::cout << "Connection accepted from " << clientIP << ":" << ntohs(clientAddr.sin_port) << std::endl;

        // Optional: Restrict to specific client IP
        if (strcmp(clientIP, "192.168.1.234") != 0) {
            std::cerr << "Unauthorized client attempted to connect. Closing connection." << std::endl;
            closesocket(clientSocket);
            continue;
        }

        // Receive data from the client
        char recvbuf[512];
        int recvbuflen = sizeof(recvbuf);

        int recvResult = recv(clientSocket, recvbuf, recvbuflen, 0);
        if (recvResult > 0) {
            std::string receivedData(recvbuf, recvResult);
            std::cout << "Data received: " << receivedData << std::endl;

            // Parse the received payload
            ParsedReceivedMessage payloadInfo = parseReceivedPayloadToStruct(receivedData);

            // Square the message value
            payloadInfo.message *= payloadInfo.message;

            // Prepare the response payload
            std::stringstream ss;
            ss << payloadInfo.id << ":" << payloadInfo.message;
            std::string responsePayload = ss.str();

            // Send the response back to the client
            int sendResult = send(clientSocket, responsePayload.c_str(), responsePayload.length(), 0);
            if (sendResult == SOCKET_ERROR) {
                std::cerr << "Send failed with error: " << WSAGetLastError() << std::endl;
            } else {
                std::cout << "Response sent to client: " << responsePayload << std::endl;
            }
        } else if (recvResult == 0) {
            std::cout << "Connection closing..." << std::endl;
        } else {
            std::cerr << "Receive failed with error: " << WSAGetLastError() << std::endl;
        }

        // Close the client socket
        closesocket(clientSocket);
    }

    // Cleanup
    closesocket(listenSocket);
    WSACleanup();

    return 0;
}
