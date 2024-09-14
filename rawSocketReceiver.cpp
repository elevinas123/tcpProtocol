#include <arpa/inet.h> // For inet_pton to convert IP addresses
#include <cstring>
#include <iostream>
#include <netinet/ip.h>  // For IP header structure
#include <netinet/tcp.h> // For TCP header
#include <sys/socket.h>
#include <unistd.h> // For close()

extern int sendMessage(int sockfd, char *message, uint32_t seqNum,
                       uint32_t ackNum, uint8_t syn, uint8_t ack,
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

    return recv_sockfd; // Return the receiving socket
}


int sendAckMessage(int sockfd, tcphdr * tcph,  u_int16_t port) {

    u_int32_t seqNumber = ntohl(tcph->seq);
    u_int32_t ackNumber = ntohl(tcph->ack_seq);

    if (tcph->syn ==1 && seqNumber == 0) {
        int messageSent = sendMessage(sockfd, "Test message", 0, seqNumber + 1, 1, 1, port);
        std::cout << "Tcp Ack Sent" << std::endl;
        if (messageSent == 1)
        {
            return 1;
        }
        return 0;
    }
    return 0;
}

int rawSocketReceiver() {
    u_int16_t receivingPort = 55000;
    u_int16_t messagePort = 55001;
    int recv_sockfd = createReceivingSocket(receivingPort);
    int message_sockfd = createSendingSocket();
    if (recv_sockfd < 0)
    {
        return 1;
    }

    std::cout << "Starting TCP packet receiver on port " << receivingPort << "..." << std::endl;

    // Step 2: Buffer to receive the packet
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    
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
            continue; // Ignore non-TCP packets
        }

        // Extract TCP header
        struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4);

        // Filter: Only process packets sent to port 55000
        if (ntohs(tcph->dest) != receivingPort) {
            continue; // Ignore packets not sent to port 55000
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

        if (data_size > header_size) {
            char *payload = buffer + header_size;
            int payload_size = data_size - header_size;
            std::cout << "Payload: " << std::string(payload, payload_size) << std::endl;
        } else {
            std::cout << "No payload" << std::endl;
        }

        int ackSent = sendAckMessage(message_sockfd, tcph, messagePort);

        // Handle sending ACK or responses here if needed
    }

    // Close the receiving socket
    close(recv_sockfd);
    return 0;
}
