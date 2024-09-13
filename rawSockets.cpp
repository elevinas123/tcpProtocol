#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>   // For IP header structure
#include <netinet/ip_icmp.h>  // For ICMP header
#include <arpa/inet.h>    // For inet_pton to convert IP addresses
#include <unistd.h>       // For close()


extern int sendMessage(int sockfd, char* message);
extern int rawSocketReceiver();
int main() {
    std::cout << "Starting ICMP server" << std::endl;
    std::cout << "Are you receiver or sender? 0 for receiver, 1 for sender" << std::endl;
    int choice;
    std::cin >> choice;
    if (choice == 0) {
        rawSocketReceiver();
        return 1;
    }
    else if (choice == 1)
    {
        // Step 1: Create a raw socket for sending ICMP packets
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd < 0) {
            perror("Socket creation failed");
            return 1;
        }

        // Step 2: Set socket option to include IP header
        int one = 1;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt failed");
            return 1;
        }
        for (int i = 0; i < 10; i++) {
            
            char message[50];  // Ensure the buffer is large enough to hold the string plus the integer
            sprintf(message, "Hello, ICMP! %d", i);

            sendMessage(sockfd, message);
            std::cout << "Sending message: " << message << std::endl;
            
        }

        std::cout << "ICMP packet with message sent successfully!" << std::endl;

        // Step 11: Close the socket
        close(sockfd);
        return 0;
    }
    else
    {
        std::cout << "Invalid choice" << std::endl;
        return 1;
    }
}
