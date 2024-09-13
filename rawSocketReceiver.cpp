#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>   // For IP header structure
#include <netinet/ip_icmp.h>  // For ICMP header
#include <unistd.h>       // For close()
#include <arpa/inet.h>

int rawSocketReceiver() {
    std::cout << "Starting ICMP packet receiver..." << std::endl;
    // Step 1: Create a raw socket to receive ICMP packets
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }
    // Step 2: Allow socket reuse to avoid issues with leftover packets
    int one = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        perror("setsockopt failed");
        return 1;
    }
    // Step 2: Buffer to receive the packet
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    // Step 3: Receive packets in a loop
    while (true) {
        struct sockaddr saddr;
        socklen_t saddr_len = sizeof(saddr);

        // Step 4: Receive the packet
        int data_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, &saddr, &saddr_len);
        if (data_size < 0) {
            perror("recvfrom failed");
            return 1;
        }

        // Step 5: Extract IP header
        struct iphdr *iph = (struct iphdr *) buffer;

        std::cout << "ICMP Packet received!" << std::endl;
        std::cout << "Source IP: " << inet_ntoa(*(struct in_addr *)&iph->saddr) << std::endl;
        std::cout << "Version: " << iph->version << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(*(struct in_addr *)&iph->daddr) << std::endl;
        // Extract and print the payload (message)
        char *received_message = buffer + sizeof(struct iphdr) + sizeof(struct icmphdr);
        std::cout << "Received message: " << received_message << std::endl;

        // Continue to receive packets
    }

    // Step 6: Close the socket
    close(sockfd);
    std::cout << "Socket closed" << std::endl;
    return 0;
}
