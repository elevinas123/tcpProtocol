#include <arpa/inet.h>    // For inet_pton to convert IP addresses
#include <netinet/ip.h>   // For IP header structure
#include <netinet/tcp.h>  // For TCP header
#include <sys/socket.h>
#include <unistd.h>  // For close()

#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

extern int sendMessage(int sockfd,
                       char *message,
                       uint32_t seqNum,
                       uint32_t ackNum,
                       uint8_t syn,
                       uint8_t ack,
                       uint16_t port);

extern int rawSocketReceiver();
extern int createReceivingSocket(u_int16_t receivingPort);

int createSendingSocket() {
    // Step 1: Create a raw socket for sending TCP packets
    int message_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (message_sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Step 2: Set socket option to include IP header
    int one = 1;
    if (setsockopt(message_sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt failed");
        return -1;
    }

    return message_sockfd;  // Return the sending socket
}

int main() {
    std::cout << "Starting TCP server" << std::endl;
    std::cout << "Are you receiver or sender? 0 for receiver, 1 for sender" << std::endl;
    int choice;
    std::cin >> choice;
    if (choice == 0) {
        rawSocketReceiver();  // Start the receiver
    } else if (choice == 1) {
        std::ifstream file("messagesFile.txt");  // Open the file for reading
        if (!file.is_open()) {
            std::cerr << "Failed to open file." << std::endl;
            return 1;
        }

        std::vector<char *> lines;  // Vector to store lines as char*

        std::string line;
        // Read each line from the file
        while (std::getline(file, line)) {
            // Allocate memory for each line, +1 for the null terminator
            char *cstr = new char[line.length() + 1];
            // Copy the line to the dynamically allocated char*
            std::strcpy(cstr, line.c_str());
            // Store the char* in the vector
            lines.push_back(cstr);
        }

        file.close();  // Close the file

        // Print the stored lines
        for (const char *line : lines) {
            std::cout << line << std::endl;
        }

        u_int16_t messagePort = 55000;
        u_int16_t receivingPort = 55001;
        u_int32_t sequenceNumber = 0;
        // Create separate sockets for sending and receiving
        int message_sockfd = createSendingSocket();
        int receive_sockfd = createReceivingSocket(receivingPort);
        bool ackReceived = false;
        bool handshakeCompleted = false;
        int messagesSent = 0;
        if (message_sockfd < 0) {
            return 1;
        }

        // Prepare destination address for sending
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);  // Destination IP

        // Send the initial SYN packet
        int messageSent = sendMessage(message_sockfd, "", sequenceNumber, 0, 1, 0, messagePort);
        sequenceNumber++;
        std::cout << "TCP SYN packet sent to port: " << messagePort << std::endl;

        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));

        // Step 3: Receive packets in a loop
        while (true) {
            struct sockaddr saddr;
            socklen_t saddr_len = sizeof(saddr);

            // Receive the packet
            int data_size = recvfrom(receive_sockfd, buffer, sizeof(buffer), 0, &saddr, &saddr_len);
            if (data_size < 0) {
                perror("recvfrom failed");
                close(receive_sockfd);
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
            // Filter: Only process packets sent to receivingPort
            if (ntohs(tcph->dest) != receivingPort) {
                continue;  // Ignore packets not sent to the receiving port
            }
            // Respond to SYN-ACK by sending ACK
            u_int32_t seqNumberReceived = ntohl(tcph->seq);
            u_int32_t ackNumberReceived = ntohl(tcph->ack_seq);

            // Print the packet information
            std::cout << "TCP Packet received on port: " << receivingPort << std::endl;
            std::cout << "Source IP: " << inet_ntoa(*(struct in_addr *)&iph->saddr) << std::endl;
            std::cout << "Source Port: " << ntohs(tcph->source) << std::endl;
            std::cout << "SYN Flag: " << (tcph->syn ? "1" : "0") << std::endl;
            std::cout << "ACK Flag: " << (tcph->ack ? "1" : "0") << std::endl;
            std::cout << "Sequence Number: " << seqNumberReceived << std::endl;
            std::cout << "ACK Number: " << ackNumberReceived << std::endl;

            // Handle any payload
            int ip_header_len = iph->ihl * 4;
            int tcp_header_len = tcph->doff * 4;
            int header_size = ip_header_len + tcp_header_len;

            if (data_size > header_size) {
                char *payload = buffer + header_size;
                int payload_size = data_size - header_size;
                std::cout << "Payload: " << std::string(payload, payload_size) << std::endl;
            } else {
                std::cout << "No payload" << std::endl;
            }
            std::cout << std::endl;

            // Check if this is a SYN-ACK response
            if (tcph->syn == 1 && tcph->ack == 1 && !handshakeCompleted) {
                if (ackNumberReceived == sequenceNumber) {
                    std::cout << "SYN-ACK received. Sending ACK..." << std::endl;
                    // Send the final ACK to complete the handshake
                    int ackSent = sendMessage(message_sockfd, "", sequenceNumber,
                                              seqNumberReceived + 1, 0, 1, messagePort);
                    std::cout << "ACK sent successfully to complete handshake!" << std::endl;
                    if (ackSent == 0) {
                        // After the Ack was send to complete the handShake, send the first data
                        handshakeCompleted = true;
                        char *message = lines[messagesSent];
                        int messageSent = sendMessage(message_sockfd, message, sequenceNumber,
                                                      seqNumberReceived + 1, 0, 0, messagePort);
                        if (messageSent == 0) {
                            std::cout << "Message Sent" << std::endl;
                            messagesSent++;
                            sequenceNumber += strlen(message);
                        }
                    }
                } else {
                    std::cout << "Wrong ack number received, expected: " << sequenceNumber + 1
                              << ", received: " << ackNumberReceived << std::endl;
                }
                continue;
            }
            if (tcph->ack == 1 && handshakeCompleted && messagesSent < lines.size()) {
                if (ackNumberReceived == sequenceNumber) {
                    char *message = lines[messagesSent];
                    int messageSent = sendMessage(message_sockfd, message, sequenceNumber,
                                                  seqNumberReceived + 1, 0, 0, messagePort);
                    if (messageSent == 0) {
                        std::cout << "Message Sent" << std::endl;
                        messagesSent++;
                        sequenceNumber += strlen(message);
                    }
                } else {
                    std::cout << "Wrong ack number received, expected: " << sequenceNumber + 1
                              << ", received: " << ackNumberReceived << std::endl;
                }
            } else if (handshakeCompleted) {
                int messageSent = sendMessage(message_sockfd, "", sequenceNumber,
                                              seqNumberReceived + 1, 0, 1, messagePort);
                if (messageSent == 0) {
                    std::cout << "Ack Sent" << std::endl;
                }
            }
            
        }

        // Close the receiving socket
        close(receive_sockfd);
        return 0;
    } else {
        std::cout << "Invalid choice" << std::endl;
        return 1;
    }

    return 0;
}
