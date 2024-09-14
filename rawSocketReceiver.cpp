#include <arpa/inet.h>    // For inet_pton to convert IP addresses
#include <netinet/ip.h>   // For IP header structure
#include <netinet/tcp.h>  // For TCP header
#include <sys/socket.h>
#include <unistd.h>  // For close()

#include <cstring>
#include <iostream>

extern int sendMessage(int sockfd,
                       char *message,
                       uint32_t seqNum,
                       uint32_t ackNum,
                       uint8_t syn,
                       uint8_t ack,
                       uint16_t port);

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

        // Print the packet information
        std::cout << "TCP Packet received on port: " << receivingPort << std::endl;
        std::cout << "Source IP: " << inet_ntoa(*(struct in_addr *)&iph->saddr) << std::endl;
        std::cout << "Source Port: " << ntohs(tcph->source) << std::endl;
        std::cout << "SYN Flag: " << (tcph->syn ? "1" : "0") << std::endl;
        std::cout << "ACK Flag: " << (tcph->ack ? "1" : "0") << std::endl;
        std::cout << "Sequence Number: " << ntohl(tcph->seq) << std::endl;
        std::cout << "ACK Number: " << ntohl(tcph->ack_seq) << std::endl;

        // Handle any payload
        int ip_header_len = iph->ihl * 4;
        int tcp_header_len = tcph->doff * 4;
        int header_size = ip_header_len + tcp_header_len;
        int payloadSize = 0;
        if (data_size > header_size) {
            char *payload = payload = buffer + header_size;
            payloadSize = data_size - header_size;
            std::cout << "Payload: " << std::string(payload, payloadSize) << std::endl;
            std::cout << "Payload Size: " << payloadSize << std::endl;
        } else {
            std::cout << "No payload" << std::endl;
        }
        std::cout << " " << std::endl;

        // Respond with ACK if SYN is set
        u_int32_t seqNumberReceived = ntohl(tcph->seq);
        u_int32_t ackNumberReceived = ntohl(tcph->ack_seq);

        if (!handshakeCompleted && tcph->syn == 1) {
            std::cout << "SYN received, sending SYN-ACK..." << std::endl;
            int ackSent = sendMessage(message_sockfd, "", sequenceNumber,
                                      seqNumberReceived + 1,  // Acknowledge the SYN
                                      1,                      // SYN = 0 for ACK
                                      1,                      // ACK = 1 to acknowledge SYN
                                      messagePort             // Send to the source port
            );

            if (ackSent == 0) {
                handshakeCompleted = true;
                sequenceNumber++;
                std::cout << "SYN-ACK sent" << std::endl;
            }
        }
        // If this is the SYN packet, send back ACK
        if (handshakeCompleted && tcph->ack == 0) {
            std::cout << "is handshake done? " << handshakeCompleted << std::endl;
            std::cout << "SYN received, sending ACK..." << std::endl;
            int ackSent = sendMessage(message_sockfd, "ACK for SYN", sequenceNumber,
                                      seqNumberReceived + payloadSize,  // Acknowledge the SYN
                                      0,                                // SYN = 0 for ACK
                                      1,           // ACK = 1 to acknowledge SYN
                                      messagePort  // Send to the source port
            );
            if (ackSent == 0) {
                std::cout << "ACK sent for SYN!" << std::endl;
            }
            char *message = "labas";
            int messageSent = sendMessage(message_sockfd, message, sequenceNumber,
                                          seqNumberReceived, 0, 0, messagePort);
            if (messageSent == 0) {
                std::cout << "Message Sent" << std::endl;
                messagesSent++;
                sequenceNumber += strlen(message);
            }

        } else if (tcph->ack == 1) {
            // Simply acknowledge any other packets with the current sequence number
            std::cout << "ACK received, no further action required." << std::endl;
        }
    }
    // Close the receiving socket
    close(recv_sockfd);
    return 0;
}