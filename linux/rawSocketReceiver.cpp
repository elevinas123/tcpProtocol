#include <arpa/inet.h>    // For inet_pton to convert IP addresses
#include <netinet/ip.h>   // For IP header structure
#include <netinet/tcp.h>  // For TCP header
#include <sys/socket.h>
#include <unistd.h>  // For close()

#include <cstring>
#include <iostream>
#include <sstream>  // For std::stringstream

extern int sendMessage(int sockfd,
                       char *message,
                       uint32_t seqNum,
                       uint32_t ackNum,
                       uint8_t syn,
                       uint8_t ack,
                       uint16_t port,
                       bool isLinux);
extern int createSendingSocket();

int createReceivingSocket(u_int16_t receivingPort) {
    // Step 1: Create a raw socket to receive TCP packets
    int recv_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Step 2: Bind the socket to a specific port to listen for incoming packets
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(receivingPort);  // Receiver port
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(recv_sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(recv_sockfd);
        return -1;
    }

    return recv_sockfd;  // Return the receiving socket
}
struct ParsedReceivedMessage {
    std::string id;  // Identifier string
    int message;     // The message value as an integer
};

ParsedReceivedMessage parseReceivedPayloadToStruct(const std::string &payload) {
    ParsedReceivedMessage parsed;

    // Find the position of the colon (:) separating id and message
    size_t delimiter_pos = payload.find(':');
    if (delimiter_pos != std::string::npos) {
        // Extract the id from the payload
        parsed.id = payload.substr(0, delimiter_pos);

        // Extract the message (as a string) and convert it to an integer
        std::string message_str = payload.substr(delimiter_pos + 1);
        parsed.message = std::stoi(message_str);  // Convert to int
    } else {
        // Handle invalid payload (no colon found)
        std::cerr << "Invalid payload format: " << payload << std::endl;
        parsed.id = "";
        parsed.message = 0;
    }

    return parsed;  // Return the parsed struct
}
int rawSocketReceiver() {
    u_int16_t receivingPort = 55000;
    u_int16_t messagePort = 55001;  // Assuming client is sending from this port
    int recv_sockfd = createReceivingSocket(receivingPort);
    int message_sockfd = createSendingSocket();
    bool handshakeCompleted = false;
    u_int32_t sequenceNumber = 100;
    if (recv_sockfd < 0) {
        return 1;
    }

    std::cout << "Starting TCP packet receiver on port " << receivingPort << "..." << std::endl;

    // Step 2: Buffer to receive the packet
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    int messagesSent = 0;
    // Step 3: Receive packets in a loop
    while (true) {
        struct sockaddr saddr;
        socklen_t saddr_len = sizeof(saddr);

        // Receive the packet
        int data_size = recvfrom(recv_sockfd, buffer, sizeof(buffer), 0, &saddr, &saddr_len);
        if (data_size < 0) {
            perror("recvfrom failed");
            close(recv_sockfd);
            return 1;
        }

        // Extract IP header
        struct iphdr *iph = (struct iphdr *)buffer;

        // Filter: Only process TCP packets
        if (iph->protocol != IPPROTO_TCP) {
            continue;  // Ignore non-TCP packets
        }

        // Extract TCP header
        struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4);

        // Filter: Only process packets sent to port 55000
        if (ntohs(tcph->dest) != receivingPort) {
            continue;  // Ignore packets not sent to port 55000
        }

        // Respond to SYN-ACK by sending ACK
        u_int32_t seqNumberReceived = ntohl(tcph->seq);
        u_int32_t ackNumberReceived = ntohl(tcph->ack_seq);

        // Handle any payload
        int ip_header_len = iph->ihl * 4;
        int tcp_header_len = tcph->doff * 4;
        int header_size = ip_header_len + tcp_header_len;
        int payloadSize = 0;
        std::string payload;

        // Check if there is any payload
        if (data_size > header_size) {
            char *payload_char = buffer + header_size;
            int payloadSize = data_size - header_size;

            // Convert payload to std::string
            payload = std::string(payload_char, payloadSize);
            std::cout << "Payload as std::string: " << payload << std::endl;
        } else {
            std::cout << "No payload" << std::endl;
        }

        if (!handshakeCompleted && tcph->syn == 1) {
            std::cout << "SYN received, sending SYN-ACK..." << std::endl;
            int ackSent = sendMessage(message_sockfd, "", sequenceNumber,
                                      seqNumberReceived + 1,  // Acknowledge the SYN
                                      1,                      // SYN = 0 for ACK
                                      1,                      // ACK = 1 to acknowledge SYN
                                      messagePort,
                                      false  // Send to the source port
            );

            if (ackSent == 0) {
                handshakeCompleted = true;
                sequenceNumber++;
                std::cout << "SYN-ACK sent" << std::endl;
                std::cout << " " << std::endl;
            }
            continue;
        }
        // If this is the SYN packet, send back ACK
        if (handshakeCompleted && tcph->ack == 0) {
            int ackSent = sendMessage(message_sockfd, "", sequenceNumber,
                                      seqNumberReceived + payloadSize,  // Acknowledge the SYN
                                      0,                                // SYN = 0 for ACK
                                      1,            // ACK = 1 to acknowledge SYN
                                      messagePort,  // Send to the source port
                                      false);
            if (ackSent != 0) {
                std::cout << "Failed to send ACK" << std::endl;
            }
            if (payload.size() < 1) continue;
            // Assuming payloadInfo has been parsed and message has been processed
            ParsedReceivedMessage payloadInfo = parseReceivedPayloadToStruct(payload);

            // Example: Square the message value (int)
            payloadInfo.message *= payloadInfo.message;  // Modify the message by squaring it

            // Step 1: Convert the message (int) to string and concatenate it with the id
            std::stringstream ss;
            ss << payloadInfo.id << ":" << payloadInfo.message;  // Format: "id:message"

            // Step 2: Get the final payload string
            std::string payloadStr = ss.str();

            // Step 3: Allocate a char* buffer for the payload
            size_t messageLength = payloadStr.length() + 1;  // Include space for null terminator
            char *charPayload = new char[messageLength];     // Dynamically allocate memory

            // Step 4: Copy the std::string into the char* buffer
            std::strcpy(charPayload, payloadStr.c_str());  // Copy payload string to char*

            // Now you have the payload ready to send in charPayload, which is a char*
            // Example output
            std::cout << "Prepared payload to send: " << charPayload << std::endl;
            int messageSent = sendMessage(message_sockfd, charPayload, sequenceNumber,
                                          seqNumberReceived, 0, 0, messagePort, false);
            if (messageSent == 0) {
                std::cout << "Message Sent" << std::endl;
                messagesSent++;
                sequenceNumber += strlen(charPayload);
            }

        } else if (tcph->ack == 1) {
            // Simply acknowledge any other packets with the current sequence number
            std::cout << "ACK received, no further action required." << std::endl;
        }
        std::cout << std::endl;
    }
    // Close the receiving socket
    close(recv_sockfd);
    return 0;
}