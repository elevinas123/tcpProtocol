#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>   // For IP header structure
#include <netinet/ip_icmp.h>  // For ICMP header
#include <arpa/inet.h>    // For inet_pton to convert IP addresses
#include <unistd.h>       // For close()


// Function to calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    for (sum = 0; len > 1; len -= 2){
        sum += *buf++;  // First add the value, then increment the pointer
    }
    if (len == 1){
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}



int sendMessage(int sockfd, char* message) {
    // Step 3: Allocate buffer for the packet (IP header + ICMP header + payload)
    std::cout << "Sending ICMP packet with message..." << std::endl;
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    // Step 4: Create IP header
    struct iphdr *iph = (struct iphdr *) buffer;
    iph->ihl = 5;            // Header length (5 * 32-bit words = 20 bytes)
    iph->version = 4;        // IPv4
    iph->tos = 0;            // Type of service
    iph->id = htonl(54321);  // Identification
    iph->frag_off = 0;       // No fragmentation
    iph->ttl = 64;           // Time to live (TTL)
    iph->protocol = IPPROTO_ICMP;  // ICMP protocol
    iph->saddr = inet_addr("127.0.0.1");  // Source IP (loopback)
    iph->daddr = inet_addr("127.0.0.1C");  // Destination IP (loopback)

    // Step 5: Create ICMP header
    struct icmphdr *icmph = (struct icmphdr *)(buffer + sizeof(struct iphdr));
    icmph->type = ICMP_ECHO;  // ICMP echo request
    icmph->code = 0;          // Echo request code
    icmph->un.echo.id = htons(1234);  // Identifier
    icmph->un.echo.sequence = htons(1);  // Sequence number
    icmph->checksum = 0;      // Initial checksum

    // Step 6: Add message (payload)
    int message_len = strlen(message);
    strcpy(buffer + sizeof(struct iphdr) + sizeof(struct icmphdr), message);

    // Step 7: Calculate ICMP checksum (header + payload)
    icmph->checksum = checksum((unsigned short *)icmph, sizeof(struct icmphdr) + message_len);

    // Step 8: Set total length in IP header
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + message_len);

    // Step 9: Define destination address
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");  // Loopback address
    std::cout << "Sending ICMP packet to" << std::endl;
    // Step 10: Send the packet
    if (sendto(sockfd, buffer, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto failed");
        return 1;
    }
        
    return 0;
}
