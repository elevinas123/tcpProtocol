#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>    // For IP header structure
#include <netinet/tcp.h>   // For TCP header
#include <arpa/inet.h>     // For inet_pton to convert IP addresses
#include <unistd.h>        // For close()

// Function to calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

int sendMessage(int sockfd, char* message, uint32_t seqNum, uint32_t ackNum, uint8_t syn, uint8_t ack, uint16_t port, bool isLinux) {
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    
    
    // Step 1: Create IP header
    struct iphdr *iph = (struct iphdr *)buffer;
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    if (isLinux) {
        iph->saddr = inet_addr("192.168.1.234");
        iph->daddr = inet_addr("192.168.1.180");

    } else {
        iph->saddr = inet_addr("192.168.1.180");
        iph->daddr = inet_addr("192.168.1.234");
    }

    // Step 2: Create TCP header
    struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct iphdr));
    tcph->source = htons(12345);      // Source port
    tcph->dest = htons(port);        // Destination port 
    tcph->seq = htonl(seqNum);
    tcph->ack_seq = htonl(ackNum);
    tcph->doff = 5;
    tcph->syn = syn;
    tcph->ack = ack;
    tcph->window = htons(5840);
    tcph->check = 0;

    // Step 3: Add message (payload)
    int message_len = strlen(message);
    strcpy(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr), message);

    // Step 4: Calculate checksum using pseudo-header
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + message_len);

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + message_len;
    char *pseudogram = (char *)malloc(psize);
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + message_len);

    tcph->check = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    // Step 5: Set total length in IP header
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + message_len);

    // Step 6: Define destination address and send the packet
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph->daddr;

    if (sendto(sockfd, buffer, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto failed");
        return 1;
    }

    std::cout << "TCP packet sent successfully!" << std::endl;
    return 0;
}
