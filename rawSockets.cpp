
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

extern int rawSocketReceiver();
extern int createReceivingSocket(u_int16_t receivingPort);
int createSendingSocket()
{
    // Step 1: Create a raw socket for sending TCP packets
    int send_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (send_sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Step 2: Set socket option to include IP header
    int one = 1;
    if (setsockopt(send_sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt failed");
        return -1;
    }

    return send_sockfd; // Return the sending socket
}

int main() {
    std::cout << "Starting TCP server" << std::endl;
    std::cout << "Are you receiver or sender? 0 for receiver, 1 for sender" << std::endl;
    int choice;
    std::cin >> choice;

    if (choice == 0) {
        rawSocketReceiver(); // Start the receiver
    } else if (choice == 1) {
        u_int16_t messagePort = 55000;
        u_int16_t receivingPort = 55001;


        int send_sockfd = createSendingSocket();
        int receive_sockfd = createReceivingSocket(receivingPort);
        if (send_sockfd < 0)
        {
            return 1;
        }

        // Prepare destination address
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr); // Destination IP

        char *message = "First SYN TCP";
        int messageSent = sendMessage(send_sockfd, message, 0, 0, 1, 0, messagePort);

        std::cout << "TCP packet with message sent successfully to port: " << messagePort << std::endl;
        
        // Close the sending socket
        close(send_sockfd);
    } else {
        std::cout << "Invalid choice" << std::endl;
        return 1;
    }

    return 0;
}
