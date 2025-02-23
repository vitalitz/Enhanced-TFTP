/*
 * TFTP Client Implementation with Extended Features
 *
 * This file implements a TFTP (Trivial File Transfer Protocol) client that supports standard
 * TFTP operations such as file upload (PUT), download (GET), and deletion (DELETE). In addition
 * to basic TFTP functionality, this client offers several enhanced features:
 *
 *   1. MD5 Integrity Verification:
 *      - The client can request and compare MD5 hashes for files to ensure data integrity.
 *      - After transfers, the client computes the local MD5 hash and compares it with the server’s hash.
 *
 *   2. AES Encryption:
 *      - When enabled, the client supports secure file transfers using AES encryption.
 *      - Encrypted Read (Enc RRQ) and Write (Enc WRQ) operations allow for secure downloads and uploads.
 *
 *   3. Dynamic Buffer Size Negotiation:
 *      - The client negotiates a custom buffer size with the server to optimize transfer performance
 *        under varying network conditions.
 *
 *   4. Ephemeral Port Management:
 *      - The client employs ephemeral ports for data transfers, ensuring a clear separation between
 *        control and data channels.
 *
 *   5. Robust Command-Line Configuration:
 *      - Users can specify the server IP, port, file name, operation mode (PUT, GET, or DELETE),
 *        buffer size, MD5 verification, verbosity level, and AES key file via command-line arguments.
 *
 *   6. Detailed Logging:
 *      - Configurable verbosity levels allow for detailed logging of operations, aiding in debugging
 *        and monitoring of file transfers.
 *
 * Usage:
 *   Compile this client using a standard C compiler (e.g., gcc) and run it with the appropriate
 *   command-line arguments. For example:
 *
 *       ./tftp_client --server <IP> --port <num> (--put|--get|--delete) <file> [--buffer-size <num>] [--md5] [--verbose <N>] [--keyfile <file>]
 *
 * This client is designed to work with a TFTP server that supports these extended features,
 * providing secure, reliable file transfers with integrity verification and optimized performance.
 *
 * Author: Vitali Tziganov
 * Date: 23/02/2025
 */

 #include "md5_utils.h"      // Utility functions for computing MD5 hashes
 #include "tftp.h"           // TFTP protocol definitions and opcodes
 #include "crypto_utils.h"   // Utility functions for AES encryption/decryption
 #include <stdio.h>
 #include <stdint.h>
 #include <stdlib.h>
 #include <string.h>
 #include <arpa/inet.h>      // For IP address conversion functions
 #include <unistd.h>
 #include <sys/stat.h>
 #include <stddef.h>
 #include <sys/select.h>
 #include <sys/time.h>
 #include <ctype.h>
 #include <getopt.h>
 #include <stdarg.h>
 #include <errno.h>
 
 // Default TFTP port (UDP-based)
 #define TFTP_PORT 69
 
 // Standard data packet size for TFTP (in bytes)
 #define DATA_SIZE 512
 
 // Length of MD5 hash string (32 characters)
 #define MD5_STR_LEN 32
 
 // Maximum filename length (in bytes)
 #define MAX_FILENAME_LEN 256
 
 // Timeout for waiting for ACK (in seconds)
 #define TIMEOUT_SEC 1
 
 // Maximum number of retries before giving up on a packet transfer
 #define MAX_RETRIES 5
 
 // Default buffer size used for transfers
 #define DEFAULT_BUFFER_SIZE 512
 
 // Global configuration flags and variables:
 
 int verbose = 0;           // Verbosity level for logging (default is minimal logging)
 int md5_enable = 0;        // Flag to enable MD5 integrity verification (0 = disabled, 1 = enabled)
 int aes_enable = 0;        // Flag to enable AES encryption for secure transfers (0 = disabled, 1 = enabled)
 uint16_t buffer_size = DEFAULT_BUFFER_SIZE;  // Negotiated buffer size for file transfers (default is 512 bytes)

// Logs messages to the console if the specified verbosity level is met or exceeded.
void log_message(int verbosity, const char *format, ...);

// Sends a Read Request (RRQ) to the TFTP server to request the specified file.
void send_rrq(int sock, struct sockaddr_in *server_addr, const char *filename);

// Sends a Write Request (WRQ) to the TFTP server to initiate an upload of the specified file.
void send_wrq(int sock, struct sockaddr_in *server_addr, const char *filename);

// Sends a MD5 verification request to the server for the specified file.
// Typically used after an upload to verify the integrity of the transferred file.
void send_md5_verify(int sock, struct sockaddr_in *server_addr, const char *filename);

// Requests the MD5 hash of the specified file from the server.
// This allows the client to compare and verify file integrity.
void request_md5(int sock, struct sockaddr_in *server_addr, const char *filename);

// Sends an Encrypted Read Request (Enc RRQ) to the server for secure file download.
// This function requires that AES encryption is enabled.
void send_enc_rrq(int sock, struct sockaddr_in *server_addr, const char *filename);

// Sends an Encrypted Write Request (Enc WRQ) to the server for secure file upload.
// This function requires that AES encryption is enabled.
void send_enc_wrq(int sock, struct sockaddr_in *server_addr, const char *filename);

// Sends a DELETE request to the server to remove the specified file.
void send_delete_request(int sock, struct sockaddr_in *server_addr, const char *filename);

// Sends a buffer size synchronization request to the server to negotiate the transfer buffer size.
void send_buffer_size_sync(int sock, struct sockaddr_in *server_addr, uint16_t new_buf_size);

int main(int argc, char *argv[]) {
    // Variables to store command-line arguments.
    char *server_ip = NULL;   // Server IP address (specified with --server or -s)
    char *filename = NULL;    // Name of the file to transfer (upload/download/delete)
    char *keyfile = NULL;     // Optional AES key file (specified with --keyfile or -k)
    int port = 69;            // Default TFTP port is 69 (specified with --port or -p)
    int mode = 0;             // Operation mode: 1 = PUT (upload), 2 = GET (download), 3 = DELETE

    // Define command-line options using getopt_long.
    static struct option long_options[] = {
        // "server": requires an argument (the server IP address); short option '-s'
        {"server", required_argument, 0, 's'},  
        // "port": requires an argument (the server port number); short option '-p'
        {"port", required_argument, 0, 'p'},  
        // "put": requires an argument (the file to upload); short option '-w'
        {"put", required_argument, 0, 'w'},  
        // "get": requires an argument (the file to download); short option '-r'
        {"get", required_argument, 0, 'r'},  
        // "delete": requires an argument (the file to delete); short option '-d'
        {"delete", required_argument, 0, 'd'},
        // "buffer-size": requires an argument to specify a custom buffer size; short option '-b'
        {"buffer-size", required_argument, 0, 'b'},
        // "md5": no argument, flag to enable MD5 verification; short option '-m'
        {"md5", no_argument, 0, 'm'},  
        // "verbose": optional argument to set verbosity level; short option '-v'
        {"verbose", optional_argument, 0, 'v'},  
        // "keyfile": requires an argument (the AES key file); short option '-k'
        {"keyfile", required_argument, 0, 'k'},  
        // "help": no argument, display help message; short option '-h'
        {"help", no_argument, 0, 'h'},  
        {0, 0, 0, 0}  // End marker for options
    };

    int opt;
    // Parse command-line arguments.
    while ((opt = getopt_long(argc, argv, "s:p:w:r:d:b:mv::k:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                // Set the server IP address.
                server_ip = optarg;
                break;
            case 'p':
                // Convert the port number from string to integer.
                port = atoi(optarg);
                break;
            case 'w':
                // Set the filename for a PUT (upload) operation.
                filename = optarg;
                mode = 1;  // Mode 1 indicates PUT (upload).
                break;
            case 'r':
                // Set the filename for a GET (download) operation.
                filename = optarg;
                mode = 2;  // Mode 2 indicates GET (download).
                break;
            case 'd':
                // Set the filename for a DELETE operation.
                filename = optarg;
                mode = 3;  // Mode 3 indicates DELETE.
                break;
            case 'b':  // Handle buffer size option.
                if (optarg) {
                    buffer_size = atoi(optarg);  // Use the provided buffer size.
                } else if (optind < argc && argv[optind][0] != '-') {
                    // If the next argument is not an option, treat it as the buffer size.
                    buffer_size = atoi(argv[optind]);
                    optind++;
                } else {
                    // Fallback to default buffer size if none is provided.
                    buffer_size = DEFAULT_BUFFER_SIZE;
                }
                // Validate that the buffer size is within the acceptable range.
                if (buffer_size < 512 || buffer_size > 8192) {
                    fprintf(stderr, "❌ Error: Buffer size must be between 512 and 8192 bytes.\n");
                    return EXIT_FAILURE;
                }
                break;
            case 'm':
                // Enable MD5 integrity verification.
                md5_enable = 1;
                break;
            case 'v':  // Handle verbosity option.
                if (optarg) {
                    verbose = atoi(optarg); // Use user-provided verbosity level.
                } else if (optind < argc && argv[optind][0] != '-') {
                    verbose = atoi(argv[optind]);
                    optind++;
                } else {
                    // Default verbosity level if none provided.
                    verbose = 0;
                }
                break;
            case 'k':
                // Set the key file for AES encryption.
                keyfile = optarg;
                break;
            case 'h':
                // Display usage information and exit.
                printf("Usage: %s --server <IP> --port <num> (--put|--get|--delete) <file> [--buffer-size <num>] [--md5] [--verbose <N>] [--keyfile <file>]\n", argv[0]);
                return EXIT_SUCCESS;
            default:
                // For any unrecognized option, exit with failure.
                return EXIT_FAILURE;
        }
    }

    // Load the AES key if a key file is specified.
    if (keyfile) {
        if (load_aes_key(keyfile) < 0) {
            fprintf(stderr, "❌ Client failed to load AES key. Exiting.\n");
            return EXIT_FAILURE;
        }
        aes_enable = 1;
        printf("✅ Client AES encryption enabled.\n");
    }

    // Ensure that required arguments (server IP, filename, and operation mode) are provided.
    if (!server_ip || !filename || mode == 0) {
        fprintf(stderr, "Error: Missing required arguments.\n");
        return EXIT_FAILURE;
    }

    // Log the current verbosity level if enabled.
    if (verbose) {
        log_message(VERB_ALWAYS, "[VERBOSE] Verbose mode enabled and set to %d\n", verbose);
    }

    // Log that the client is connecting to the specified server and port.
    log_message(VERB_ALWAYS, "Connecting to server %s on port %d...\n", server_ip, port);

    int sock;
    struct sockaddr_in server_addr;

    // Create a UDP socket.
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set up the server address structure.
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    // Select and perform the requested TFTP operation based on mode.
    switch (mode)
    {
        case 1:
            // PUT (upload) mode: use encrypted write if AES is enabled, otherwise use standard write.
            if (aes_enable) {
                send_enc_wrq(sock, &server_addr, filename);
            } else {
                send_wrq(sock, &server_addr, filename);
            }
            break;
        case 2:
            // GET (download) mode: use encrypted read if AES is enabled, otherwise use standard read.
            if (aes_enable) {
                send_enc_rrq(sock, &server_addr, filename);
            } else {
                send_rrq(sock, &server_addr, filename);
            }
            break;
        case 3:
            // DELETE mode: send a delete request for the specified file.
            send_delete_request(sock, &server_addr, filename);
            break;
        default:
            // This case should not occur if arguments are correctly validated.
            fprintf(stderr, "❌ Error: Unknown mode.\n");
            close(sock);
            return EXIT_FAILURE;
    }

    // Close the socket and exit.
    close(sock);
    return 0;
}

/** 📌 Send Read Request (Download) **/
void send_rrq(int sock, struct sockaddr_in *server_addr, const char *filename) {
    // Allocate a buffer for the RRQ packet.
    // The packet size is the negotiated buffer size plus 4 bytes for the TFTP header.
    uint8_t *buffer;
    buffer = (uint8_t *)malloc(buffer_size + 4);
    
    // Calculate the length of the RRQ packet:
    // 2 bytes for opcode, the filename string (including null terminator),
    // the mode string "octet" (including null terminator).
    int len = 2 + strlen(filename) + 1 + strlen("octet") + 1;  // Opcode + Filename + Mode

    // If the client buffer size has been negotiated to a non-default value,
    // send a buffer size synchronization request to the server.
    if(buffer_size != DEFAULT_BUFFER_SIZE) {
        send_buffer_size_sync(sock, server_addr, buffer_size);
    }

    // Clear the allocated buffer.
    memset(buffer, 0, buffer_size + 4);

    // Prepare the RRQ packet:
    // Set the opcode to OP_RRQ (after converting to network byte order).
    uint16_t opcode = htons(OP_RRQ);
    // Copy the opcode into the first 2 bytes of the buffer.
    memcpy(buffer, &opcode, sizeof(opcode));  // ✅ Safe memory alignment

    // Copy the filename (including its null terminator) into the buffer right after the opcode.
    memcpy(buffer + 2, filename, strlen(filename) + 1);

    // Copy the mode string "octet" (including null terminator) after the filename.
    memcpy(buffer + 2 + strlen(filename) + 1, "octet", strlen("octet") + 1);

    // Send the RRQ packet to the server.
    sendto(sock, buffer, len, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));
    log_message(VERB_DEBUG, "📤 RRQ for %s sent.\n", filename);

    // ------------------------------
    // Prepare to receive the file data.
    // ------------------------------

    // Open a local file for writing in binary mode. This is where the received file will be saved.
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("❌ Error opening file");
        return;
    }

    // Set a timeout for receiving data packets to avoid blocking indefinitely.
    struct timeval timeout;
    timeout.tv_sec = 1;      // 1-second timeout for data packets.
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // ------------------------------
    // Wait for the first DATA packet to determine the new transfer port.
    // ------------------------------

    struct sockaddr_in server_response;
    socklen_t addr_len = sizeof(server_response);
    uint8_t *recv_buffer;
    recv_buffer = (uint8_t *)malloc(buffer_size + 4);

    // Receive the first DATA packet from the server.
    ssize_t bytes_received = recvfrom(sock, recv_buffer, buffer_size + 4, 0, 
        (struct sockaddr *)&server_response, &addr_len);

    if (bytes_received < 0) {
        perror("recvfrom failed");
        log_message(VERB_ALWAYS, "❌ Error: No response from server.\n");
        fclose(file);
        return;
    }

    // Update the server address with the new ephemeral port provided in the response.
    server_addr->sin_port = server_response.sin_port;
    log_message(VERB_VERBOSE, "✅ Server switched to port %d\n", ntohs(server_addr->sin_port));

    // ------------------------------
    // Begin receiving file data.
    // ------------------------------

    uint16_t block = 1;           // TFTP data blocks start at 1.
    uint16_t last_ack_block = 0;  // Track the last acknowledged block.
    int retries = 3;              // Maximum 3 retransmissions per block.

    while (1) {
        // If no data is received (less than header size), handle retransmission.
        if (bytes_received < 4) {
            if (retries-- > 0) {
                // No packet received: resend the last ACK to prompt retransmission.
                log_message(VERB_ALWAYS, "⚠ No data received, retransmitting ACK for Block=%d\n", last_ack_block);
                
                uint8_t ack_packet[4];
                *(uint16_t *)ack_packet = htons(OP_ACK);
                *(uint16_t *)(ack_packet + 2) = htons(last_ack_block);

                sendto(sock, ack_packet, 4, 0, (struct sockaddr *)server_addr, addr_len);
                
                // Try to receive the packet again.
                bytes_received = recvfrom(sock, recv_buffer, buffer_size + 4, 0, 
                                          (struct sockaddr *)&server_response, &addr_len);
                continue;
            } else {
                log_message(VERB_ALWAYS, "❌ Error: No response from server after multiple retries.\n");
                break;
            }
        }

        // Extract the opcode and block number from the received packet.
        uint16_t received_opcode = ntohs(*(uint16_t *)recv_buffer);
        uint16_t received_block = ntohs(*(uint16_t *)(recv_buffer + 2));
        uint16_t data_size = bytes_received - 4;  // Calculate size of the data payload.

        // Verify that the received packet is a DATA packet.
        if (received_opcode != OP_DATA) {
            log_message(VERB_ALWAYS, "❌ Unexpected opcode received: %d\n", received_opcode);
            break;
        }

        if (received_block == block) {
            // Valid block received.
            log_message(VERB_ALWAYS, "📥 Received DATA: Block=%d, Bytes=%d\n", received_block, data_size);

            // Write the received data (after the 4-byte header) to the file.
            fwrite(recv_buffer + 4, 1, data_size, file);

            // Prepare and send an ACK for this block.
            uint8_t ack_packet[4];
            *(uint16_t *)ack_packet = htons(OP_ACK);
            *(uint16_t *)(ack_packet + 2) = htons(block);

            sendto(sock, ack_packet, 4, 0, (struct sockaddr *)server_addr, addr_len);
            log_message(VERB_DEBUG, "📤 Sent ACK for Block=%d\n", block);

            last_ack_block = block;  // Update the last acknowledged block.
            retries = 3;             // Reset the retry counter for the next block.
            
            // Check if this is the final data packet.
            if (data_size < buffer_size) {
                log_message(VERB_ALWAYS, "✅ Transfer complete!\n");
                break;
            }

            block++;  // Move to the next block.
        } else if (received_block < block) {
            // Duplicate block received, resend ACK without writing duplicate data.
            log_message(VERB_VERBOSE, "⚠ Duplicate Block=%d received, resending ACK\n", received_block);

            uint8_t ack_packet[4];
            *(uint16_t *)ack_packet = htons(OP_ACK);
            *(uint16_t *)(ack_packet + 2) = htons(received_block);

            sendto(sock, ack_packet, 4, 0, (struct sockaddr *)server_addr, addr_len);
        } else {
            // Received an out-of-order block: log error and ignore it.
            log_message(VERB_ALWAYS, "❌ Out-of-order Block=%d received (expected=%d), ignoring.\n", received_block, block);
        }

        // Attempt to receive the next DATA packet.
        bytes_received = recvfrom(sock, recv_buffer, buffer_size + 4, 0, 
                                  (struct sockaddr *)&server_response, &addr_len);
    }

    // Close the file and log the file save operation.
    fclose(file);
    log_message(VERB_ALWAYS, "💾 File saved as: %s\n", filename);
    close(sock);

    // ------------------------------
    // Optionally, perform MD5 verification if enabled.
    // ------------------------------
    if (md5_enable) {
        log_message(VERB_DEBUG, "🔄 Reopening socket for MD5 request...\n");

        // Close the current socket.
        close(sock);

        // Create a new UDP socket for the MD5 request.
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("❌ Error: Could not create new socket for MD5 request.");
            return;
        }

        // Reset the server port to the default TFTP port (69) for the MD5 request.
        server_addr->sin_port = htons(69);

        // Send an MD5 request to verify file integrity.
        request_md5(sock, server_addr, filename);
        close(sock);  // Close the socket after the MD5 request.
    }

    free(recv_buffer);  // Free the allocated receive buffer.
    free(buffer);       // Free the allocated buffer used for the RRQ.
}

/** 📌 Send Write Request (Upload) **/
void send_wrq(int sock, struct sockaddr_in *server_addr, const char *filename) {
    // Allocate a buffer for the WRQ packet. The packet size is the negotiated buffer_size plus 4 bytes for the header.
    uint8_t *buffer;
    buffer = (uint8_t *)malloc(buffer_size + 4);

    // Prepare the WRQ opcode in network byte order.
    uint16_t opcode = htons(OP_WRQ);

    // If a custom buffer size is used (not the default), negotiate the buffer size with the server.
    if (buffer_size != DEFAULT_BUFFER_SIZE) {
        send_buffer_size_sync(sock, server_addr, buffer_size);
    }

    // Clear the allocated buffer.
    memset(buffer, 0, buffer_size + 4);
    
    // Copy the opcode into the first 2 bytes of the buffer.
    memcpy(buffer, &opcode, sizeof(opcode));
    
    // Copy the filename (including its null terminator) into the buffer right after the opcode.
    memcpy(buffer + 2, filename, strlen(filename) + 1);

    // Calculate total packet length: 2 bytes (opcode) + filename length + 1 (null terminator)
    // For WRQ, only opcode and filename are required.
    sendto(sock, buffer, strlen(filename) + 3, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));
    log_message(VERB_DEBUG, "📤 Sent WRQ for %s\n", filename);

    // ------------------------------
    // Wait for the server's ACK to the WRQ.
    // ------------------------------
    struct sockaddr_in server_response;
    socklen_t addr_len = sizeof(server_response);
    uint8_t *recv_buffer;
    recv_buffer = (uint8_t *)malloc(buffer_size + 4);

    // Log that we're waiting for an ACK from the server.
    log_message(VERB_DEBUG, "🔄 Waiting for ACK...\n");
    
    // Wait for server's response (ACK packet).
    ssize_t bytes_received = recvfrom(sock, recv_buffer, buffer_size + 4, 0, 
                                        (struct sockaddr *)&server_response, &addr_len);
    if (bytes_received < 4) {
        log_message(VERB_ALWAYS, "❌ Error: No valid ACK received for WRQ\n");
        return;
    }
    log_message(VERB_DEBUG, "✅ ACK received for WRQ\n");

    // ------------------------------
    // Extract the new port assigned by the server.
    // ------------------------------
    // The server includes its new ephemeral port in the ACK packet at offset 4.
    server_addr->sin_port = *(uint16_t *)(recv_buffer + 4);  // Read assigned port from ACK.
    log_message(VERB_DEBUG, "🔄 Server switched to port %d\n", ntohs(server_addr->sin_port));

    // Verify the ACK packet's opcode and block number (should be ACK for block 0).
    uint16_t received_opcode = ntohs(*(uint16_t *)recv_buffer);
    uint16_t received_block = ntohs(*(uint16_t *)(recv_buffer + 2));
    if (received_opcode != OP_ACK || received_block != 0) {
        log_message(VERB_ALWAYS, "❌ Error: Unexpected ACK response for WRQ\n");
        return;
    }

    // ------------------------------
    // Create a new UDP socket for data transfer.
    // ------------------------------
    // Close the original socket and create a new one bound to an ephemeral port.
    close(sock);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("❌ Error: Could not create new socket for data transfer.");
        return;
    }

    // Bind the client socket to an ephemeral port.
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // Bind to any available interface.
    client_addr.sin_port = htons(0);  // Let the OS assign an ephemeral port.

    if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("❌ Error: Could not bind to ephemeral port.");
        close(sock);
        return;
    }

    // Retrieve and log the ephemeral port assigned to the client.
    socklen_t client_addr_len = sizeof(client_addr);
    getsockname(sock, (struct sockaddr *)&client_addr, &client_addr_len);
    log_message(VERB_DEBUG, "🔄 Client using ephemeral port %d for data transfer\n", ntohs(client_addr.sin_port));

    // ------------------------------
    // Set a timeout for receiving ACKs during data transfer.
    // ------------------------------
    struct timeval timeout;
    timeout.tv_sec = 1;  // Set a 1-second timeout for ACK reception.
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // ------------------------------
    // Open the file to be uploaded.
    // ------------------------------
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("❌ Error opening file");
        close(sock);
        return;
    }

    // Initialize the block number for data packets (TFTP blocks start at 1).
    uint16_t block = 1;

    // Begin transferring file data in blocks.
    while (1) {
        // Allocate a buffer for the data packet (header + data payload).
        uint8_t *data_packet;
        data_packet = (uint8_t *)malloc(buffer_size + 4);
        memset(data_packet, 0, buffer_size + 4);

        // Read up to buffer_size bytes from the file into the data packet (after header space).
        uint16_t read_bytes = fread(data_packet + 4, 1, buffer_size, file);
        if (read_bytes == 0) {
            log_message(VERB_ALWAYS, "✅ File transfer complete!\n");
            break;  // End of file reached.
        }

        // Set up the TFTP data packet header.
        *(uint16_t *)data_packet = htons(OP_DATA);
        *(uint16_t *)(data_packet + 2) = htons(block);

        // ------------------------------
        // Retransmission handling: attempt to send this block and wait for ACK.
        // ------------------------------
        int retries = 3;  // Maximum of 3 retransmissions per block.
        while (retries--) {
            // Send the data packet (header + payload) to the server.
            sendto(sock, data_packet, read_bytes + 4, 0, (struct sockaddr *)server_addr, addr_len);
            log_message(VERB_DEBUG, "📤 Sent Block=%d (%zu bytes) to %s:%d (Retries left: %d)\n", 
                        block, read_bytes, inet_ntoa(server_addr->sin_addr), ntohs(server_addr->sin_port), retries);

            // Wait for the ACK corresponding to the current block.
            log_message(VERB_DEBUG, "🔄 Waiting for ACK for Block %d...\n", block);
            bytes_received = recvfrom(sock, recv_buffer, buffer_size + 4, 0, 
                                      (struct sockaddr *)&server_response, &addr_len);

            if (bytes_received >= 4) {
                // Extract opcode and block number from the ACK.
                received_opcode = ntohs(*(uint16_t *)recv_buffer);
                received_block = ntohs(*(uint16_t *)(recv_buffer + 2));

                // If the ACK is valid for the current block, log success and break out of the retry loop.
                if (received_opcode == OP_ACK && received_block == block) {
                    log_message(VERB_DEBUG, "✅ ACK received for Block %d\n", block);
                    break;  // Proceed to the next block.
                }
                // Log an error if an unexpected ACK is received.
                log_message(VERB_ALWAYS, "❌ Error: Unexpected ACK for Block %d (Received Block=%d)\n", block, received_block);
            } else {
                // Log a warning if no ACK was received, then retry.
                log_message(VERB_DEBUG, "⚠ No ACK received for Block %d, retransmitting...\n", block);
            }
        }

        free(data_packet);  // Free the allocated data packet buffer.

        // If no valid ACK was received after all retransmissions, abort the transfer.
        if (retries < 0) {
            log_message(VERB_ALWAYS, "❌ Error: Block %d lost after multiple attempts\n", block);
            break;
        }

        // If the number of bytes read is less than the full buffer size, this was the last block.
        if (read_bytes < buffer_size) {
            log_message(VERB_DEBUG, "✅ Final Block Sent (Block %d, %zu bytes)\n", block, read_bytes);
            break;
        }

        // Move to the next block.
        block++;
    }

    // Close the file after the transfer is complete.
    fclose(file);
    log_message(VERB_ALWAYS, "✅ Upload complete: %s\n", filename);
    close(sock);

    // ------------------------------
    // Optionally perform MD5 verification if enabled.
    // ------------------------------
    if (md5_enable) {
        log_message(VERB_DEBUG, "🔄 Reopening socket for MD5 request...\n");

        // Create a new socket for the MD5 request.
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("❌ Error: Could not create new socket for MD5 request.");
            return;
        }

        // Reset the server port to the default TFTP port (69) for the MD5 request.
        server_addr->sin_port = htons(69);
        // Send the MD5 verification request.
        send_md5_verify(sock, server_addr, filename);
        close(sock);
    }

    log_message(VERB_ALWAYS, "🔒 Socket closed, client finished.\n");

    free(recv_buffer);  // Free the allocated receive buffer.
    free(buffer);       // Free the allocated buffer used for the WRQ.
}

void log_message(int verbosity, const char *format, ...) {
    // Declare a variable argument list to handle the variadic arguments.
    va_list args;
    // Initialize the va_list with the variable arguments starting after 'format'.
    va_start(args, format);

    // Only log the message if the provided verbosity level is less than or equal
    // to the global verbosity level 'verbose'.
    if (verbosity <= verbose) {
        // Print the formatted message to stdout using the variable arguments.
        vprintf(format, args);
        // Flush stdout to ensure that the output is immediately displayed.
        fflush(stdout);
    }

    // Clean up the va_list to prevent resource leaks.
    va_end(args);
}

void send_md5_verify(int sock, struct sockaddr_in *server_addr, const char *filename) {
    // The 'sock' parameter is unused here because we create a separate socket for the MD5 request.
    (void)sock;  // Suppress unused variable warning

    // Allocate a buffer for constructing the MD5 verification request.
    // The buffer size is based on the negotiated buffer_size.
    uint8_t *buffer;
    buffer = (uint8_t *)malloc(buffer_size);

    // Prepare the opcode for MD5 verification in network byte order.
    uint16_t opcode = htons(OP_MD5_VERIFY);

    // Clear the allocated buffer.
    memset(buffer, 0, buffer_size);

    // Copy the MD5 verification opcode into the first 2 bytes of the buffer.
    memcpy(buffer, &opcode, sizeof(opcode));
    
    // Copy the filename (including its null terminator) into the buffer immediately after the opcode.
    memcpy(buffer + 2, filename, strlen(filename) + 1);

    // Compute the MD5 hash for the file.
    // md5_hash will store the 32-character MD5 string plus a null terminator.
    char md5_hash[33];
    if (!compute_md5(filename, md5_hash)) {
        // If MD5 computation fails, log an error and exit the function.
        log_message(VERB_ALWAYS, "❌ Error computing MD5 for %s\n", filename);
        return;
    }

    // Copy the computed MD5 hash (32 characters) into the buffer at offset 258.
    // The offset is predetermined by the protocol structure for MD5 verification requests.
    memcpy(buffer + 258, md5_hash, 32);

    /** 
     * Force the MD5 verification request to use the control port (69).
     * This ensures the request is sent to the correct TFTP control port rather than a data port.
     */
    server_addr->sin_port = htons(69);
    
    // Create a new UDP socket dedicated to the MD5 verification request.
    // This prevents interference with the main data transfer socket.
    int md5_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (md5_sock < 0) {
        perror("❌ Error: Could not create new socket for MD5 request.");
        return;
    }

    // Log that the MD5 verification request is being sent.
    log_message(VERB_NORMAL, "📤 Sent MD5 verification request for %s\n", filename);

    // Send the MD5 verification request.
    // The total packet length is 258 (offset before MD5) + 32 (MD5 hash) bytes.
    sendto(md5_sock, buffer, 258 + 32, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));

    /** 
     * Wait for the MD5 verification response from the server.
     * A timeout of 1 second is set to prevent indefinite blocking.
     */
    struct timeval timeout;
    timeout.tv_sec = 1;  // 1-second timeout
    timeout.tv_usec = 0;
    setsockopt(md5_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Prepare to receive the MD5 response (a single byte).
    uint8_t response;
    socklen_t server_len = sizeof(*server_addr);
    ssize_t recv_len = recvfrom(md5_sock, &response, 1, 0, (struct sockaddr *)server_addr, &server_len);

    if (recv_len >= 1) {
        // Log the received MD5 verification response.
        log_message(VERB_VERBOSE, "✅ MD5 response received: %d\n", response);
        if (response == 1) {
            log_message(VERB_VERBOSE, "✅ File MD5 matches!\n");
        } else {
            log_message(VERB_ALWAYS, "❌ File MD5 mismatch!\n");
        }
    } else {
        // If no response is received, log an error with the errno value and description.
        log_message(VERB_ALWAYS, "⚠️ No MD5 response received. errno=%d (%s)\n", errno, strerror(errno));
    }

    /** 
     * Close the dedicated MD5 verification socket.
     * This ensures that the MD5 operation does not interfere with other communications.
     */
    close(md5_sock);
    log_message(VERB_DEBUG, "🔒 MD5 verification socket closed.\n");

    free(buffer);  // Free the allocated buffer used for the MD5 verification request.
}

void request_md5(int sock, struct sockaddr_in *server_addr, const char *filename) {
    // Allocate a buffer for constructing the MD5 request packet.
    // The buffer size is based on the negotiated buffer_size.
    uint8_t *buffer;
    buffer = (uint8_t *)malloc(buffer_size);

    // Prepare the MD5 request opcode in network byte order.
    uint16_t opcode = htons(OP_MD5_REQUEST);
    
    // Clear the allocated buffer.
    memset(buffer, 0, buffer_size);

    // Copy the opcode into the first 2 bytes of the buffer.
    memcpy(buffer, &opcode, sizeof(opcode));

    // Copy the filename (including the null terminator) into the buffer right after the opcode.
    memcpy(buffer + 2, filename, strlen(filename) + 1);

    // Send the MD5 request packet to the server.
    // The total length of the packet is 2 bytes (opcode) + filename length + 1 (null terminator).
    sendto(sock, buffer, strlen(filename) + 3, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));
    log_message(VERB_DEBUG, "📤 Sent MD5 request for %s\n", filename);

    // Prepare a buffer to receive the server's MD5 hash response.
    // The MD5 hash is expected to be 32 characters, so we allocate 33 bytes to include the null terminator.
    char server_md5[33];

    // Receive the MD5 hash from the server.
    // We don't need the sender's address here, so NULL is passed for those parameters.
    recvfrom(sock, server_md5, 33, 0, NULL, NULL);

    // Ensure the received MD5 string is null-terminated.
    server_md5[32] = '\0';

    // Log the MD5 hash received from the server.
    log_message(VERB_DEBUG, "✅ Server MD5:\t%s\n", server_md5);

    // Compute the local MD5 hash for the specified file.
    char local_md5[33];
    if (compute_md5(filename, local_md5)) {
        // Log the locally computed MD5 hash.
        log_message(VERB_VERBOSE, "💾 Local MD5:\t%s\n", local_md5);
        // Compare the local MD5 hash with the server's hash.
        if (strcmp(server_md5, local_md5) == 0) {
            log_message(VERB_VERBOSE, "✅ MD5 Match!\n");
        } else {
            log_message(VERB_ALWAYS, "❌ MD5 Mismatch!\n");
        }
    } else {
        // Log an error if the local MD5 computation fails.
        log_message(VERB_ALWAYS, "❌ Error computing local MD5\n");
    }

    // Free the allocated request buffer.
    free(buffer);
}

void send_enc_rrq(int sock, struct sockaddr_in *server_addr, const char *filename) {
    // Allocate a buffer for the encrypted RRQ packet.
    // The buffer size is the negotiated 'buffer_size' plus 4 bytes for the TFTP header.
    uint8_t *buffer;
    buffer = (uint8_t *)malloc(buffer_size + 4);

    // Prepare the encrypted RRQ opcode (OP_ENC_RRQ) in network byte order.
    uint16_t opcode = htons(OP_ENC_RRQ);

    // If a custom buffer size has been negotiated (i.e., not the default),
    // send a buffer size synchronization request to the server.
    if(buffer_size != DEFAULT_BUFFER_SIZE) {
        send_buffer_size_sync(sock, server_addr, buffer_size);
    }

    // Clear the allocated buffer.
    memset(buffer, 0, buffer_size + 4);

    // Copy the opcode into the first 2 bytes of the buffer.
    memcpy(buffer, &opcode, sizeof(opcode));
    // Copy the filename (including its null terminator) right after the opcode.
    memcpy(buffer + 2, filename, strlen(filename) + 1);

    // Send the encrypted RRQ packet to the server.
    // The packet length is 2 (opcode) + filename length + 1 (null terminator).
    sendto(sock, buffer, strlen(filename) + 3, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));
    log_message(VERB_DEBUG, "📤 Sent Encrypted RRQ for %s\n", filename);

    // Open a local file for writing the downloaded content (in binary mode).
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("❌ Error opening file");
        return;
    }

    // Prepare to receive the first DATA packet, which also indicates the new transfer port.
    struct sockaddr_in server_response;
    socklen_t addr_len = sizeof(server_response);
    uint8_t *recv_buffer;
    recv_buffer = (uint8_t *)malloc(buffer_size + 4);

    // Set a timeout on the socket to prevent blocking indefinitely while waiting for data.
    struct timeval timeout;
    timeout.tv_sec = 1;      // 1-second timeout for data packets.
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Wait for the first DATA packet (typically Block 0, used for port switching).
    log_message(VERB_DEBUG, "🔄 Waiting for next block...\n");
    size_t bytes_received = recvfrom(sock, recv_buffer, buffer_size + 4, 0, 
                                (struct sockaddr *)&server_response, &addr_len);
    log_message(VERB_DEBUG, "🔄 Received Block=%d (%d byte)\n", 0, (int)(bytes_received - 4));

    // Update the server address structure with the new ephemeral port from the response.
    server_addr->sin_port = server_response.sin_port;

    // Initialize the AES Initialization Vector (IV).
    // The same IV must be used for decryption as was used during encryption.
    uint8_t iv[AES_BLOCK_SIZE] = {0};

    // Initialize block counters and retry management.
    uint16_t block = 1;
    uint16_t last_ack_block = 0;  // Track the last block for which an ACK was sent.
    int retries = 3;              // Maximum 3 retransmissions per block.

    // Begin loop to receive subsequent DATA packets containing the file data.
    while (1) {
        // If the received packet is too short (less than 4 bytes), handle as a timeout.
        if (bytes_received < 4) {
            if (retries-- > 0) {
                // No data received: resend the last ACK to prompt retransmission.
                log_message(VERB_VERBOSE, "⚠ No data received, retransmitting ACK for Block=%d\n", last_ack_block);
                
                uint8_t ack_packet[4];
                *(uint16_t *)ack_packet = htons(OP_ACK);
                *(uint16_t *)(ack_packet + 2) = htons(last_ack_block);
                sendto(sock, ack_packet, 4, 0, (struct sockaddr *)server_addr, addr_len);
                
                // Attempt to receive the packet again.
                bytes_received = recvfrom(sock, recv_buffer, buffer_size + 4, 0, 
                                          (struct sockaddr *)&server_response, &addr_len);
                continue;
            } else {
                log_message(VERB_ALWAYS, "❌ Error: No response from server after multiple retries.\n");
                break;
            }
        }

        // Extract the opcode and block number from the received packet.
        uint16_t received_opcode = ntohs(*(uint16_t *)recv_buffer);
        uint16_t received_block = ntohs(*(uint16_t *)(recv_buffer + 2));
        // Calculate the size of the data payload.
        uint16_t data_size = bytes_received - 4;

        // Verify that the received packet is a DATA packet.
        if (received_opcode != OP_DATA) {
            log_message(VERB_ALWAYS, "❌ Unexpected opcode received: %d\n", received_opcode);
            break;
        }

        if (received_block == block) {
            // Valid block received: proceed with decryption and writing data.
            // Decrypt the data portion (after the 4-byte header) using the shared IV.
            aes_decrypt(recv_buffer + 4, data_size, iv);
            // Write the decrypted data to the local file.
            fwrite(recv_buffer + 4, 1, data_size, file);

            // Prepare and send an ACK for the current block.
            uint8_t ack_packet[4];
            *(uint16_t *)ack_packet = htons(OP_ACK);
            *(uint16_t *)(ack_packet + 2) = htons(block);
            sendto(sock, ack_packet, 4, 0, (struct sockaddr *)server_addr, addr_len);
            log_message(VERB_DEBUG, "📤 Sent ACK for Block=%d\n", block);

            // Update the last acknowledged block and reset retries.
            last_ack_block = block;
            retries = 3;
            
            // If the data payload is smaller than the full buffer, assume it is the final block.
            if (data_size < buffer_size) {
                log_message(VERB_ALWAYS, "✅ Encrypted Transfer complete!\n");
                break;
            }

            // Increment the block counter for the next expected block.
            block++;
        } else if (received_block < block) {
            // Duplicate block received: resend the ACK for that block.
            log_message(VERB_VERBOSE, "⚠ Duplicate Block=%d received, resending ACK\n", received_block);
            uint8_t ack_packet[4];
            *(uint16_t *)ack_packet = htons(OP_ACK);
            *(uint16_t *)(ack_packet + 2) = htons(received_block);
            sendto(sock, ack_packet, 4, 0, (struct sockaddr *)server_addr, addr_len);
        } else {
            // Out-of-order block received: log error and ignore it.
            log_message(VERB_ALWAYS, "❌ Out-of-order Block=%d received (expected=%d), ignoring.\n", received_block, block);
        }

        // Wait for the next block.
        log_message(VERB_DEBUG, "🔄 Waiting for next block...\n");
        bytes_received = recvfrom(sock, recv_buffer, buffer_size + 4, 0, 
                                  (struct sockaddr *)&server_response, &addr_len);
        log_message(VERB_DEBUG, "🔄 Received Block=%d (%d byte)\n", block, (int)(bytes_received - 4));
    }

    // Close the file after the transfer is complete.
    fclose(file);
    log_message(VERB_ALWAYS, "💾 File saved as: %s\n", filename);
    close(sock);

    // ------------------------------
    // Optionally perform MD5 verification if enabled.
    // ------------------------------
    if (md5_enable) {
        log_message(VERB_VERBOSE, "🔄 Reopening socket for MD5 request...\n");

        // Close the current socket and create a new one for the MD5 request.
        close(sock);
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("❌ Error: Could not create new socket for MD5 request.");
            return;
        }

        // Reset the server port to the default control port (69) for the MD5 request.
        server_addr->sin_port = htons(69);
        // Send the MD5 request to verify the integrity of the transferred file.
        request_md5(sock, server_addr, filename);
        close(sock);  // Close the MD5 request socket.
    }

    free(recv_buffer);  // Free the allocated receive buffer.
    free(buffer);       // Free the allocated buffer used for the RRQ.
}

void send_enc_wrq(int sock, struct sockaddr_in *server_addr, const char *filename) {
    // Allocate a buffer for constructing the WRQ (Write Request) packet.
    // The buffer size is the negotiated buffer_size plus 4 bytes for the TFTP header.
    uint8_t *buffer;
    buffer = (uint8_t *)malloc(buffer_size + 4);

    // Prepare the encrypted WRQ opcode in network byte order.
    uint16_t opcode = htons(OP_ENC_WRQ);

    // If the client is using a non-default buffer size, negotiate the buffer size with the server.
    if(buffer_size != DEFAULT_BUFFER_SIZE) {
        send_buffer_size_sync(sock, server_addr, buffer_size);
    }

    // Clear the allocated buffer.
    memset(buffer, 0, buffer_size + 4);
    // Copy the opcode into the first 2 bytes of the buffer.
    memcpy(buffer, &opcode, sizeof(opcode));
    // Copy the filename (including its null terminator) immediately following the opcode.
    memcpy(buffer + 2, filename, strlen(filename) + 1);

    // 📤 Send the encrypted WRQ request to the server.
    // The total packet length is 2 bytes (opcode) + filename length + 1 (null terminator).
    sendto(sock, buffer, strlen(filename) + 3, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));
    log_message(VERB_DEBUG, "📤 Sent Encrypted WRQ for %s\n", filename);

    // ------------------------------
    // Wait for the server's ACK for the WRQ.
    // ------------------------------
    struct sockaddr_in server_response;
    socklen_t addr_len = sizeof(server_response);
    uint8_t *recv_buffer;
    recv_buffer = (uint8_t *)malloc(buffer_size + 4);

    // 🔄 Wait for the ACK from the server.
    log_message(VERB_DEBUG, "🔄 Waiting for ACK...\n");
    ssize_t bytes_received = recvfrom(sock, recv_buffer, buffer_size + 4, 0, 
                                    (struct sockaddr *)&server_response, &addr_len);
    // For WRQ, the ACK must be at least 6 bytes (opcode, block, and port).
    if (bytes_received < 6) {
        log_message(VERB_ALWAYS, "❌ Error: No valid ACK received for WRQ\n");
        return;
    }
    log_message(VERB_DEBUG, "✅ ACK received for WRQ\n");

    // ------------------------------
    // Extract the server's new ephemeral port from the ACK.
    // ------------------------------
    // The new port is provided in the ACK packet at offset 4.
    server_addr->sin_port = *(uint16_t *)(recv_buffer + 4);
    log_message(VERB_DEBUG, "🔄 Server switched to port %d\n", ntohs(server_addr->sin_port));

    // Verify that the ACK has the expected opcode and block number (should be ACK for block 0).
    uint16_t received_opcode = ntohs(*(uint16_t *)recv_buffer);
    uint16_t received_block = ntohs(*(uint16_t *)(recv_buffer + 2));
    if (received_opcode != OP_ACK || received_block != 0) {
        log_message(VERB_ALWAYS, "❌ Error: Unexpected ACK response for WRQ\n");
        return;
    }

    // ------------------------------
    // Create a new UDP socket for data transfer.
    // ------------------------------
    // Close the original socket and create a new one bound to an ephemeral port.
    close(sock);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_message(VERB_ALWAYS, "❌ Error: Could not create new socket for data transfer.");
        return;
    }

    // Bind the new client socket to an ephemeral port.
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // Bind to any available interface.
    client_addr.sin_port = htons(0);  // Let the OS assign an ephemeral port.
    if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("❌ Error: Could not bind to ephemeral port.");
        close(sock);
        return;
    }

    // Retrieve and log the ephemeral port assigned to the client.
    socklen_t client_addr_len = sizeof(client_addr);
    getsockname(sock, (struct sockaddr *)&client_addr, &client_addr_len);
    log_message(VERB_DEBUG, "🔄 Client using ephemeral port %d for data transfer\n", ntohs(client_addr.sin_port));

    // ------------------------------
    // Set a timeout for receiving ACKs during the data transfer.
    // ------------------------------
    struct timeval timeout;
    timeout.tv_sec = 1;      // Set a 1-second timeout for ACK reception.
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // ------------------------------
    // Open the file to be uploaded in binary read mode.
    // ------------------------------
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("❌ Error opening file");
        close(sock);
        return;
    }

    // Initialize the AES initialization vector (IV).
    // The same IV must be used across all blocks.
    uint8_t iv[AES_BLOCK_SIZE] = {0};
    // Initialize the block counter (TFTP blocks start at 1).
    uint16_t block = 1;

    // ------------------------------
    // Begin reading the file and sending encrypted data packets.
    // ------------------------------
    while (1) {
        // Allocate a buffer for the data packet (header + data).
        uint8_t *data_packet;
        data_packet = (uint8_t *)malloc(buffer_size + 4);
        memset(data_packet, 0, buffer_size + 4);

        // Read up to buffer_size bytes from the file into the data packet (after the 4-byte header).
        uint16_t read_bytes = fread(data_packet + 4, 1, buffer_size, file);
        if (read_bytes == 0) {
            log_message(VERB_ALWAYS, "✅ File transfer complete!\n");
            break;  // End-of-file reached.
        }

        // 🔐 Encrypt the data read from the file using AES and the shared IV.
        aes_encrypt(data_packet + 4, read_bytes, iv);

        // Set the TFTP data packet header: first 2 bytes are opcode (OP_DATA), next 2 bytes are block number.
        *(uint16_t *)data_packet = htons(OP_DATA);
        *(uint16_t *)(data_packet + 2) = htons(block);

        // ------------------------------
        // Retransmission handling: attempt to send the packet and wait for ACK.
        // ------------------------------
        int retries = 3;  // Maximum of 3 retransmissions per block.
        while (retries--) {
            // 📤 Send the encrypted data packet to the server.
            sendto(sock, data_packet, read_bytes + 4, 0, (struct sockaddr *)server_addr, addr_len);
            log_message(VERB_DEBUG, "📤 Sent Encrypted Block=%d (%zu bytes) to %s:%d (Retries left: %d)\n", 
                        block, read_bytes, inet_ntoa(server_addr->sin_addr), ntohs(server_addr->sin_port), retries);

            // 🔄 Wait for the ACK corresponding to the current block.
            log_message(VERB_DEBUG, "🔄 Waiting for ACK for Block %d...\n", block);
            bytes_received = recvfrom(sock, recv_buffer, buffer_size, 0, 
                                      (struct sockaddr *)&server_response, &addr_len);

            if (bytes_received >= 4) {
                // Extract the opcode and block number from the received ACK.
                received_opcode = ntohs(*(uint16_t *)recv_buffer);
                received_block = ntohs(*(uint16_t *)(recv_buffer + 2));

                // If the ACK is valid for the current block, log success and break out of the retransmission loop.
                if (received_opcode == OP_ACK && received_block == block) {
                    log_message(VERB_DEBUG, "✅ ACK received for Block %d\n", block);
                    break;  // ACK received, proceed to next block.
                }
                log_message(VERB_ALWAYS, "❌ Error: Unexpected ACK for Block %d (Received Block=%d)\n", block, received_block);
            } else {
                // Log a warning if no ACK is received and continue retransmitting.
                log_message(VERB_DEBUG, "⚠ No ACK received for Block %d, retransmitting...\n", block);
            }
        }

        free(data_packet);  // Free the allocated data packet buffer.

        // If all retransmissions failed for the current block, abort the transfer.
        if (retries < 0) {
            log_message(VERB_ALWAYS, "❌ Error: Block %d lost after multiple attempts\n", block);
            break;
        }

        // If the number of bytes read is less than the full buffer size, it indicates the final block.
        if (read_bytes < buffer_size) {
            log_message(VERB_ALWAYS, "✅ Final Block Sent (Block %d, %zu bytes)\n", block, read_bytes);
            break;  // Exit loop: file transfer complete.
        }

        // Increment the block counter for the next data packet.
        block++;
    }

    // Close the file after finishing the transfer.
    fclose(file);
    log_message(VERB_ALWAYS, "✅ Upload complete: %s\n", filename);
    close(sock);

    // ------------------------------
    // Optionally perform MD5 verification if enabled.
    // ------------------------------
    if (md5_enable) {
        log_message(VERB_DEBUG, "🔄 Reopening socket for MD5 request...\n");

        // Create a new socket for the MD5 verification request.
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("❌ Error: Could not create new socket for MD5 request.");
            return;
        }

        // Reset the server port to the default TFTP port (69) for the MD5 request.
        server_addr->sin_port = htons(69);
        // Send the MD5 verification request.
        send_md5_verify(sock, server_addr, filename);
        // Close the MD5 request socket.
        close(sock);
    }

    log_message(VERB_ALWAYS, "🔒 Socket closed, client finished.\n");

    free(recv_buffer);  // Free the allocated receive buffer.
    free(buffer);       // Free the allocated buffer used for the WRQ.
}

void send_delete_request(int sock, struct sockaddr_in *server_addr, const char *filename) {
    // Allocate a buffer to construct the DELETE request packet.
    // The size of the buffer is determined by the negotiated buffer_size.
    uint8_t *buffer;
    buffer = (uint8_t *)malloc(buffer_size);

    // Prepare the DELETE opcode in network byte order.
    uint16_t opcode = htons(OP_DELETE);

    // Clear the allocated buffer.
    memset(buffer, 0, buffer_size);

    // Copy the DELETE opcode into the first 2 bytes of the buffer.
    memcpy(buffer, &opcode, sizeof(opcode));

    // Copy the filename (with its null terminator) into the buffer starting at offset 2.
    memcpy(buffer + 2, filename, strlen(filename) + 1);

    // Log that a DELETE request is being sent.
    log_message(VERB_ALWAYS, "📤 Sending DELETE request for %s\n", filename);

    // Send the DELETE request packet to the server.
    // The total packet length is 2 (opcode) + filename length + 1 (null terminator) = strlen(filename) + 3 bytes.
    sendto(sock, buffer, strlen(filename) + 3, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));

    // ------------------------------
    // Prepare to receive the server's ACK or an ERROR response.
    // ------------------------------
    struct sockaddr_in server_response;
    socklen_t addr_len = sizeof(server_response);

    // Allocate a buffer to receive the server's response.
    uint8_t *recv_buffer;
    recv_buffer = (uint8_t *)malloc(buffer_size);

    // Set a 1-second timeout on the socket to prevent waiting indefinitely for a response.
    struct timeval timeout;
    timeout.tv_sec = 1;  // 1-second timeout for DELETE ACK reception.
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Initialize a retry counter for handling potential timeouts.
    int retries = 3;
    while (retries--) {
        // Wait for the server's response (ACK or ERROR) with the specified timeout.
        ssize_t bytes_received = recvfrom(sock, recv_buffer, buffer_size, 0,
                                          (struct sockaddr *)&server_response, &addr_len);

        if (bytes_received >= 4) {
            // Extract the opcode and block number from the response.
            uint16_t received_opcode = ntohs(*(uint16_t *)recv_buffer);
            uint16_t received_block = ntohs(*(uint16_t *)(recv_buffer + 2));

            // If the server responds with an ACK for block 0, the deletion is confirmed.
            if (received_opcode == OP_ACK && received_block == 0) {
                log_message(VERB_ALWAYS, "✅ File deletion confirmed by server.\n");
                return;
            }

            // If the server responds with an ERROR, log the error message.
            if (received_opcode == OP_ERROR) {
                log_message(VERB_ALWAYS, "❌ Server responded with error: %s\n", recv_buffer + 4);
                return;
            }
        } else {
            // If no valid response is received, log a warning and retry sending the DELETE request.
            log_message(VERB_ALWAYS, "⚠ No DELETE ACK received, retrying (%d left)...\n", retries);
            sendto(sock, buffer, strlen(filename) + 3, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));
        }
    }

    // If all retries are exhausted without a valid response, log a final error.
    log_message(VERB_ALWAYS, "❌ ERROR: No response from server, delete failed.\n");

    free(recv_buffer);  // Free the allocated receive buffer.
    free(buffer);       // Free the allocated buffer used for the DELETE request.
}

void send_buffer_size_sync(int sock, struct sockaddr_in *server_addr, uint16_t new_buf_size) {
    // Allocate a fixed-size 4-byte buffer to construct the sync request.
    // The sync packet consists of a 2-byte opcode and a 2-byte buffer size.
    uint8_t buffer[4];
    
    // Write the opcode (OP_BUF_SIZE_SYNC) into the first 2 bytes, converting to network byte order.
    *(uint16_t *)buffer = htons(OP_BUF_SIZE_SYNC);
    
    // Write the new buffer size (new_buf_size) into the next 2 bytes in network byte order.
    *(uint16_t *)(buffer + 2) = htons(new_buf_size);

    // Log that the buffer size sync request is being sent.
    log_message(VERB_VERBOSE, "📤 Sending buffer size sync request: %d bytes\n", new_buf_size);
    
    // Send the sync packet to the server.
    sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)server_addr, sizeof(*server_addr));

    // ------------------------------
    // Wait for the server's response (ACK or ERROR)
    // ------------------------------
    
    // Prepare to store the server's response.
    struct sockaddr_in server_response;
    socklen_t addr_len = sizeof(server_response);
    
    // Allocate a buffer to receive the server's response.
    // The size is based on the negotiated buffer_size.
    uint8_t *recv_buffer;
    recv_buffer = (uint8_t *)malloc(buffer_size);
    
    // Set a 1-second timeout on the socket to avoid blocking indefinitely.
    struct timeval timeout = {1, 0};  // 1-second timeout (tv_sec = 1, tv_usec = 0)
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Receive the server's response.
    ssize_t recv_len = recvfrom(sock, recv_buffer, buffer_size, 0, 
                                (struct sockaddr *)&server_response, &addr_len);

    // Check if a valid response (at least 4 bytes) was received.
    if (recv_len >= 4) {
        // Extract the opcode from the response.
        uint16_t opcode = ntohs(*(uint16_t *)recv_buffer);

        if (opcode == OP_ACK) {
            // If the response is an ACK, log a confirmation message.
            log_message(VERB_ALWAYS, "✅ Buffer size synchronized: %d bytes\n", new_buf_size);
            return;
        } else if (opcode == OP_ERROR) {
            // If the server returned an error, log a warning and note that the default buffer size will be used.
            log_message(VERB_ALWAYS, "⚠️ Server rejected buffer size change. Proceeding with default buffer size.\n");
        }
    } else {
        // If no valid response is received, log a warning.
        log_message(VERB_ALWAYS, "⚠️ No response from server. Proceeding with default buffer size.\n");
    }
    
    free(recv_buffer);
}
