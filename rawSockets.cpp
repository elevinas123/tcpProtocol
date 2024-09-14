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
struct ParsedMessage {
    int id;       // Identifier string
    int message;  // The message value as an integer
};

ParsedMessage parsePayloadToStruct(const std::string &payload) {
    ParsedMessage parsed;

    // Find the position of the colon (:) separating id and message
    size_t delimiter_pos = payload.find(':');
    if (delimiter_pos != std::string::npos) {
        // Extract the id from the payload
        parsed.id = std::stoi(payload.substr(0, delimiter_pos));

        // Extract the message (as a string) and convert it to an integer
        std::string message_str = payload.substr(delimiter_pos + 1);
        parsed.message = std::stoi(message_str);  // Convert to int
    } else {
        // Handle invalid payload (no colon found)
        std::cerr << "Invalid payload format: " << payload << std::endl;
        parsed.id = -1;
        parsed.message = 0;
    }

    return parsed;  // Return the parsed struct
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

        struct MessageInfo {
            int index;           // Index in the vector (id)
            uint32_t seq_start;  // Starting sequence number of the message
            uint32_t seq_end;    // Ending sequence number (seq_start + message length)
            bool completed;      // Whether the message has been acknowledged
            char *messageSent;   // The message itself, including the id
            int messageReceived;
        };

        std::vector<MessageInfo> messageInfoVector;
        uint32_t next_seq_num = 0;

        for (size_t i = 0; i < lines.size(); ++i) {
            char *original_message = lines[i];

            // Include the id (index) into the message
            // Calculate the length needed for the message with id
            size_t id_length = std::to_string(i).length();
            size_t original_length = strlen(original_message);
            size_t message_length =
                id_length + 1 + original_length + 1;  // id + ':' + message + '\0'

            // Allocate memory for the new message
            char *message_with_id = new char[message_length];

            // Format the message to include the id
            snprintf(message_with_id, message_length, "%zu:%s", i, original_message);

            MessageInfo info;
            info.index = i;
            info.seq_start = next_seq_num;
            info.seq_end = next_seq_num + strlen(message_with_id);
            info.completed = false;
            info.messageSent = message_with_id;  // Store the message with id
            info.messageReceived = -1;
            messageInfoVector.push_back(info);

            next_seq_num = info.seq_end;  // Update for next message
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

            // Now you can access the payload string here
            if (!payload.empty()) {
                std::cout << "Accessing payload outside of if: " << payload << std::endl;
            }

            // Check if this is a SYN-ACK response
            if (tcph->syn == 1 && tcph->ack == 1 && !handshakeCompleted) {
                if (ackNumberReceived == sequenceNumber) {
                    std::cout << "SYN-ACK received. Sending ACK..." << std::endl;
                    // Send the final ACK to complete the handshake
                    int ackSent = sendMessage(message_sockfd, "", sequenceNumber,
                                              seqNumberReceived + 1, 0, 1, messagePort);
                    std::cout << "ACK sent successfully to complete handshake!" << std::endl;
                    handshakeCompleted = true;
                } else {
                    std::cout << "Wrong ack number received, expected: " << sequenceNumber + 1
                              << ", received: " << ackNumberReceived << std::endl;
                }
                std::cout << std::endl;
            }
            if (handshakeCompleted && messagesSent < lines.size()) {
                for (int i = 0; i < messageInfoVector.size(); i++) {
                    MessageInfo messageInfo = messageInfoVector[messagesSent];

                    if (sendMessage(message_sockfd, messageInfo.messageSent, messageInfo.seq_end,
                                    ackNumberReceived, 0, 0, messagePort) != 0) {
                        std::cout << "Failed To Send Message" << std::endl;
                    }
                    std::cout << "Message Sent, Payload: " << messageInfo.messageSent << std::endl;
                    messagesSent++;
                }
            }
            if (tcph->ack == 0 && handshakeCompleted) {
                if (payload.size() > 0) {
                    ParsedMessage message = parsePayloadToStruct(payload);
                    if (message.id > -1 && message.id < messageInfoVector.size()) {
                        messageInfoVector[message.id].messageReceived = message.message;
                        messageInfoVector[message.id].completed = true;
                    } else {
                        std::cout << "Bad Packet" << std::endl;
                    }
                    int allCompleted = true;
                    for (int i = 0; i < messageInfoVector.size(); i++) {
                        if (!messageInfoVector[i].completed) {
                            allCompleted = false;
                            break;
                        }
                    }
                    if (allCompleted) {
                        std::cout << "All Messages Received" << std::endl;
                        std::cout << std::endl;
                        for (int i = 0; i < messageInfoVector.size(); i++) {
                            std::cout << "Initial num: " << messageInfoVector[i].messageSent
                                      << ", Output: " << messageInfoVector[i].messageReceived
                                      << std::endl;
                        }
                    }
                }
            }
            std::cout << std::endl;
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
