/*
 * TFTP Server Implementation with Extended Features
 *
 * This file implements a TFTP (Trivial File Transfer Protocol) server, a lightweight UDP-based
 * protocol for transferring files. In addition to supporting standard TFTP operations, this server
 * offers several extended features for enhanced security, flexibility, and robustness:
 *
 *   1. Standard TFTP Operations:
 *      - RRQ (Read Request): Clients can download files from the server.
 *      - WRQ (Write Request): Clients can upload files to the server.
 *      - DELETE: Clients can request deletion of files.
 *
 *   2. MD5 Integrity Verification:
 *      - Clients can request the MD5 hash of a file (using handle_md5_request) to verify file integrity.
 *      - After file uploads, MD5 verification (via handle_md5_verify) ensures the file was transferred
 *        without corruption.
 *
 *   3. AES Encryption Support:
 *      - Secure file transfers are enabled through AES encryption.
 *      - Encrypted Read (handle_enc_rrq) and Write (handle_enc_wrq) requests allow secure download and
 *        upload operations if encryption is enabled via a provided key file.
 *
 *   4. Dynamic Client Buffer Size Negotiation:
 *      - Clients may negotiate a custom buffer size for data transfer to optimize performance over
 *        different network conditions.
 *      - The server maintains per-client buffer sizes using a hash table (implemented with uthash).
 *
 *   5. File Backup Mechanism:
 *      - For write requests, files are initially saved as backup files (with a .bak extension).
 *      - Upon successful transfer, backups are promoted to the final filename, ensuring data integrity
 *        even if transfers are interrupted.
 *
 *   6. Robust Logging and Error Handling:
 *      - Verbose logging (with configurable verbosity levels) provides detailed insight into server
 *        operations and aids in debugging.
 *      - Standard TFTP error responses are sent to clients for issues such as file not found or access
 *        violations.
 *
 *   7. Command-Line Configuration:
 *      - The server accepts command-line arguments to specify the TFTP file directory, port, optional
 *        AES key file, and verbosity level.
 *
 * Compilation and Usage:
 *   Compile with a standard C compiler (e.g., gcc) ensuring that required libraries (like uthash) are available.
 *   Run the server as follows:
 *
 *       ./tftp_server --dir /path/to/tftp_files --port 69 [--keyfile /path/to/keyfile] [--verbose <level>]
 *
 * This implementation is designed as a lightweight, customizable TFTP server solution with extended
 * security and integrity features.
 *
 * Author: Vitali Tziganov
 * Date: 23/02/2025
 */

#include "md5_utils.h"
#include "tftp.h"
#include "crypto_utils.h"
#include "uthash.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <getopt.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/time.h>
#include <errno.h>


// ===========================
// ✅ TFTP Server Configuration
// ===========================

#define TFTP_PORT 69            // Default TFTP port (UDP-based)
#define TIMEOUT_SEC 3           // Timeout for retransmissions (in seconds)
#define MAX_RETRIES 5           // Maximum number of retries for lost packets
#define DEFAULT_BUFFER_SIZE 512 // Standard buffer size for TFTP data packets

// ==========================================================
// ✅ Client Buffer Size Tracking (For Dynamic Block Sizing)
// ==========================================================

/**
 * Structure to store buffer sizes for different clients.
 * This allows different clients to negotiate different TFTP block sizes.
 */
typedef struct {
    char client_ip[INET_ADDRSTRLEN]; // Client's IP address as a string (used as a key)
    uint16_t buffer_size;            // Buffer size negotiated for this client
    UT_hash_handle hh;               // uthash handle (for fast lookup in hash table)
} ClientBufferEntry;

ClientBufferEntry *client_buffer_table = NULL;  // Root pointer for uthash table

// ==========================
// ✅ Global Configuration Flags
// ==========================

int verbose = 0;    // Verbosity level (0 = OFF by default)
int aes_enable = 0; // AES encryption flag (0 = Disabled, 1 = Enabled)

// ===========================
// ✅ Function Declarations
// ===========================

/**
 * Logs messages depending on the verbosity level.
 * @param verbosity Minimum verbosity level required to print the message.
 * @param format    Formatted string message (printf-style).
 */
void log_message(int verbosity, const char *format, ...);

/**
 * Handles an incoming client request (RRQ/WRQ/DELETE).
 * @param sock       UDP socket descriptor.
 * @param client     Client's address and port.
 * @param client_len Size of the client struct.
 * @param buffer     Received request packet.
 * @param server_dir Path to the server's root TFTP directory.
 */
void handle_client(int sock, struct sockaddr_in *client, socklen_t client_len, uint8_t *buffer, char *server_dir);

/**
 * Handles a Read Request (RRQ) from a client (file download).
 * @param sock       UDP socket descriptor.
 * @param client     Client's address and port.
 * @param buffer     Received RRQ packet.
 * @param server_dir Path to the server's root TFTP directory.
 */
void handle_rrq(int sock, struct sockaddr_in *client, uint8_t *buffer, char *server_dir);

/**
 * Handles a Write Request (WRQ) from a client (file upload).
 * @param sock       UDP socket descriptor.
 * @param client     Client's address and port.
 * @param client_len Size of the client struct.
 * @param buffer     Received WRQ packet.
 * @param server_dir Path to the server's root TFTP directory.
 */
void handle_wrq(int sock, struct sockaddr_in *client, socklen_t client_len, uint8_t *buffer, char *server_dir);

/**
 * Sends a TFTP error packet to the client.
 * @param sock      UDP socket descriptor.
 * @param client    Client's address and port.
 * @param err_code  TFTP error code (e.g., File not found, Access violation).
 * @param message   Human-readable error message.
 */
void send_error(int sock, struct sockaddr_in *client, uint16_t err_code, const char *message);

/**
 * Handles a client's request for the MD5 hash of a file.
 * @param sock       UDP socket descriptor.
 * @param client     Client's address and port.
 * @param buffer     Received MD5 request packet.
 * @param server_dir Path to the server's root TFTP directory.
 */
void handle_md5_request(int sock, struct sockaddr_in *client, uint8_t *buffer, char *server_dir);

/**
 * Handles a client's MD5 verification request (after upload).
 * @param sock       UDP socket descriptor.
 * @param client     Client's address and port.
 * @param client_len Size of the client struct.
 * @param buffer     Received MD5 verification packet.
 * @param server_dir Path to the server's root TFTP directory.
 */
void handle_md5_verify(int sock, struct sockaddr_in *client, socklen_t client_len, uint8_t *buffer, char *server_dir);

/**
 * Handles an encrypted Read Request (RRQ).
 * Uses AES encryption to securely transfer files.
 * @param sock       UDP socket descriptor.
 * @param client     Client's address and port.
 * @param buffer     Received RRQ packet.
 * @param server_dir Path to the server's root TFTP directory.
 */
void handle_enc_rrq(int sock, struct sockaddr_in *client, uint8_t *buffer, char *server_dir);

/**
 * Handles an encrypted Write Request (WRQ).
 * Uses AES encryption to securely receive files.
 * @param sock       UDP socket descriptor.
 * @param client     Client's address and port.
 * @param client_len Size of the client struct.
 * @param buffer     Received WRQ packet.
 * @param server_dir Path to the server's root TFTP directory.
 */
void handle_enc_wrq(int sock, struct sockaddr_in *client, socklen_t client_len, uint8_t *buffer, char *server_dir);

/**
 * Handles a client's request to delete a file.
 * @param sock       UDP socket descriptor.
 * @param client     Client's address and port.
 * @param client_len Size of the client struct.
 * @param server_dir Path to the server's root TFTP directory.
 * @param filename   Name of the file to delete.
 */
void handle_delete(int sock, struct sockaddr_in *client, socklen_t client_len, const char *server_dir, const char *filename);

/**
 * Handles buffer size synchronization between client and server.
 * Ensures both agree on the same buffer size for optimized transfers.
 * @param sock       UDP socket descriptor.
 * @param client     Client's address and port.
 * @param client_len Size of the client struct.
 * @param buffer     Received buffer sync packet.
 */
void handle_buffer_size_sync(int sock, struct sockaddr_in *client, socklen_t client_len, uint8_t *buffer);

/**
 * Stores the buffer size for a specific client in the hash table.
 * @param client     Client's address and port.
 * @param buffer_size The negotiated buffer size.
 */
void store_client_buffer_size(struct sockaddr_in *client, uint16_t buffer_size);

/**
 * Retrieves the buffer size for a specific client from the hash table.
 * If no entry exists, it returns the default buffer size.
 * @param client Client's address and port.
 * @return The buffer size for the given client.
 */
uint16_t get_client_buffer_size(struct sockaddr_in *client);

/**
 * Frees all memory associated with the client buffer size hash table.
 * Should be called on server shutdown.
 */
void free_client_table();

/**
 * Removes a specific client's buffer size entry from the hash table.
 * Used when a client disconnects.
 * @param client Client's address and port.
 */
void remove_client_buffer_size(struct sockaddr_in *client);

int main(int argc, char *argv[]) {
    // Declare variables for socket, addresses, and buffer
    int sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    u_int8_t buffer[DEFAULT_BUFFER_SIZE + 4];  // Buffer to store incoming data (+ extra bytes)

    // Default port for TFTP is 69
    int port = 69;  
    // Directory for server files (must be provided)
    char *server_dir = NULL;
    // Optional key file for AES encryption (no default)
    char *keyfile = NULL;

    // Define the command-line options using getopt_long
    static struct option long_options[] = {
        {"dir", required_argument, 0, 'd'},      // Directory for TFTP files
        {"port", required_argument, 0, 'p'},       // Port number to listen on
        {"keyfile", required_argument, 0, 'k'},    // Optional AES key file for encryption
        {"verbose", optional_argument, 0, 'v'},    // Optional verbose mode (can take an argument)
        {"help", no_argument, 0, 'h'},             // Display help information
        {0, 0, 0, 0}                              // End marker for options
    };

    int opt;
    // Parse command-line options
    while ((opt = getopt_long(argc, argv, "d:p:k:v::h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                // Set server directory from argument
                server_dir = optarg;
                break;
            case 'p':
                // Convert port argument from string to integer
                port = atoi(optarg);
                break;
            case 'k':
                // Set key file for AES encryption
                keyfile = optarg;
                break;
            case 'v':
                // Set verbose level if provided; handle optional argument for verbose
                if (optarg) {
                    verbose = atoi(optarg);
                } else if (optind < argc && argv[optind][0] != '-') {
                    verbose = atoi(argv[optind]);
                    optind++;
                } else {
                    verbose = 0;  // Default verbose level if none provided
                }
                break;
            case 'h':
                // Print usage information and exit
                printf("Usage: %s --dir <path> --port <num> [--keyfile <file>]\n", argv[0]);
                return EXIT_SUCCESS;
            default:
                // On unrecognized option, exit with failure
                return EXIT_FAILURE;
        }
    }

    // Load the AES key if a key file was provided
    if (keyfile) {
        if (load_aes_key(keyfile) < 0) {
            // Print error and exit if loading the AES key fails
            fprintf(stderr, "❌ Server failed to load AES key. Exiting.\n");
            return EXIT_FAILURE;
        }
        aes_enable = 1;  // Enable AES encryption
        printf("✅ Server AES encryption enabled.\n");
    }

    // Inform that the server is ready on the specified port
    printf("✅ Server ready on port %d\n", port);

    // Ensure that the required directory argument was provided
    if (!server_dir) {
        fprintf(stderr, "Error: Missing required --dir argument.\n");
        return EXIT_FAILURE;
    }

    // If verbose mode is enabled, log the verbose level
    if (verbose) {
        log_message(VERB_ALWAYS, "[VERBOSE] Verbose mode enabled and set to %d\n", verbose);
    }

    // Check if the provided directory exists and is valid
    struct stat st;
    if (stat(server_dir, &st) == -1) {
        fprintf(stderr, "Error: Directory '%s' does not exist.\n", server_dir);
        return EXIT_FAILURE;
    }

    // Ensure the path is indeed a directory
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: '%s' is not a directory.\n", server_dir);
        return EXIT_FAILURE;
    }

    // Log the directory being used for TFTP files
    log_message(VERB_ALWAYS, "TFTP Server files directory: %s\n", server_dir);

    // Create a UDP socket for the TFTP server
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set up the server address structure for binding
    server_addr.sin_family = AF_INET;           // Use IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY;     // Bind to all available interfaces
    server_addr.sin_port = htons(port);           // Convert port to network byte order
    
    // Bind the socket to the specified port and address
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Log that the server is now listening for incoming requests
    log_message(VERB_ALWAYS, "TFTP Server listening on port %d...\n", port);

    // Main loop: continuously listen for and handle incoming TFTP requests
    while (1) {
        // Clear the buffer for the next incoming packet
        memset(buffer, 0, sizeof(buffer));
    
        // Receive data from a client; recvfrom blocks until data arrives
        ssize_t recv_len = recvfrom(sock, buffer, DEFAULT_BUFFER_SIZE+4, 0, (struct sockaddr *)&client_addr, &client_len);
        
        // Validate the received packet size; ignore packets that are too small
        if (recv_len < 2) {
            log_message(VERB_ALWAYS, "⚠️ Ignored invalid packet (size: %ld, too small)\n", recv_len);
            continue;
        }        
    
        // Handle the client request using the received data and client address
        handle_client(sock, &client_addr, client_len, buffer, server_dir);
    }    

    // Cleanup: close the socket and free any allocated resources
    close(sock);
    free_client_table();
    return EXIT_SUCCESS;
}

void handle_client(int sock, struct sockaddr_in *client, socklen_t client_len, uint8_t *buffer, char *server_dir) {

    // Extract the opcode from the first two bytes of the buffer and convert it from network to host byte order
    uint16_t opcode = ntohs(*(uint16_t *)buffer);

    // Log the received request with its opcode and the client's IP address and port
    log_message(VERB_NORMAL, "Received request: Opcode=%d from %s:%d\n",
                opcode, inet_ntoa(client->sin_addr), ntohs(client->sin_port));

    // Switch based on the opcode to determine the type of TFTP request
    switch (opcode) {
        case OP_RRQ:
            // Handle Read Request (RRQ)
            log_message(VERB_NORMAL, "📂 RRQ received.\n");
            handle_rrq(sock, client, buffer, server_dir);
            break;
        case OP_WRQ:
            // Handle Write Request (WRQ)
            log_message(VERB_NORMAL, "📂 WRQ received.\n");
            handle_wrq(sock, client, client_len, buffer, server_dir);
            break;
        case OP_MD5_VERIFY:
            // Handle MD5 Verify request (for file integrity checking)
            log_message(VERB_NORMAL, "MD5 Verify request received.\n");
            handle_md5_verify(sock, client, client_len, buffer, server_dir);
            break;
        case OP_MD5_REQUEST:
            // Handle MD5 Request (to obtain file hash)
            log_message(VERB_NORMAL, "MD5 Request received.\n");
            handle_md5_request(sock, client, buffer, server_dir);
            break;
        case OP_ENC_RRQ:
            // Handle Encrypted Read Request; only proceed if AES encryption is enabled
            if (aes_enable) {
                log_message(VERB_NORMAL, "🔒 Encrypted RRQ received. Processing with encryption.\n");
                handle_enc_rrq(sock, client, buffer, server_dir);
            } else {
                // If encryption is disabled, log an error and notify the client
                log_message(VERB_ALWAYS, "❌ Encrypted RRQ requested but encryption is disabled.\n");
                send_error(sock, client, ERR_ENCRYPTION_FAIL, "Encryption not supported on this server");
            }
            break;
        case OP_ENC_WRQ:
            // Handle Encrypted Write Request; only proceed if AES encryption is enabled
            if (aes_enable) {
                log_message(VERB_NORMAL, "🔒 Encrypted WRQ received. Processing with encryption.\n");
                handle_enc_wrq(sock, client, client_len, buffer, server_dir);
            } else {
                // If encryption is disabled, log an error and notify the client
                log_message(VERB_ALWAYS, "❌ Encrypted WRQ requested but encryption is disabled.\n");
                send_error(sock, client, ERR_ENCRYPTION_FAIL, "Encryption not supported on this server");
            }
            break;
        case OP_DELETE:
            // Handle Delete Request: delete a file from the server directory
            log_message(VERB_NORMAL, "🗑️ Delete request received.\n");
            // Skip the first 2 bytes (opcode) when passing the filename to the handler
            handle_delete(sock, client, client_len, server_dir, (char *)(buffer + 2));
            break;
        case OP_BUF_SIZE_SYNC:
            // Handle Buffer Size Synchronization request to adjust communication parameters
            log_message(VERB_NORMAL, "📥 Buffer size sync request received.\n");
            handle_buffer_size_sync(sock, client, client_len, buffer);
            break;
        default:
            // Log and respond with an error for unknown or unsupported opcodes
            log_message(VERB_NORMAL, "Invalid request opcode: %d\n", opcode);
            send_error(sock, client, ERR_ILLEGAL_OP, "Unknown TFTP operation");
    }
}

// Handle RRQ (Read Request)
void handle_rrq(int sock, struct sockaddr_in *client, uint8_t *buffer, char *server_dir) {
    // Create a filename buffer and declare a variable for the client's buffer size
    char filename[256];
    uint16_t client_buf_size;

    // Construct the full file path by concatenating the server directory and the requested filename
    // The filename in the buffer starts after the 2-byte opcode
    snprintf(filename, sizeof(filename), "%s/%s", server_dir, buffer + 2);

    // Log which file is being served to the client
    log_message(VERB_NORMAL, "📂 Serving file: %s\n", filename);

    // Attempt to open the file in read-only mode
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        // If the file can't be opened, log the error and send an error packet back to the client
        log_message(VERB_ALWAYS, "❌ Error: File not found: %s\n", filename);
        send_error(sock, client, ERR_FILE_NOT_FOUND, "File not found");
        return;
    }

    // Create a copy of the client's address for data transfer
    struct sockaddr_in data_client = *client;

    // Create a new UDP socket for the data transfer
    int data_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (data_sock < 0) {
        perror("❌ Failed to create data socket");
        log_message(VERB_ALWAYS, "❌ Error: Could not create data socket\n");
        close(fd);
        return;
    }

    // Set up a server address structure for the data socket and bind it to an ephemeral port (port 0)
    struct sockaddr_in data_server = {0};
    data_server.sin_family = AF_INET;
    data_server.sin_addr.s_addr = INADDR_ANY;
    data_server.sin_port = 0;  // Let the OS assign an ephemeral port
    if (bind(data_sock, (struct sockaddr *)&data_server, sizeof(data_server)) < 0) {
        perror("❌ Failed to bind data socket");
        log_message(VERB_ALWAYS, "❌ Error: Could not bind data socket\n");
        close(fd);
        close(data_sock);
        return;
    }

    // Retrieve and log the actual port number assigned to the data socket
    socklen_t addr_len = sizeof(data_server);
    getsockname(data_sock, (struct sockaddr *)&data_server, &addr_len);
    log_message(VERB_ALWAYS, "✅ Data socket bound to port: %d\n", ntohs(data_server.sin_port));

    // Determine the client's preferred buffer size for data transfer
    client_buf_size = get_client_buffer_size(client);
    log_message(VERB_ALWAYS, "📥 Using buffer size: %d bytes for client %s:%d\n",
        client_buf_size, inet_ntoa(client->sin_addr), ntohs(client->sin_port));

    // Initialize block number to 1 (TFTP data blocks start at 1)
    uint16_t block = 1;
    ssize_t bytes_read;
    uint8_t *data_packet;
    // Allocate memory for the data packet: client buffer size plus 4 bytes for the TFTP header
    data_packet = (uint8_t *)malloc(client_buf_size + 4);
    if (!data_packet) {
        log_message(VERB_ALWAYS, "❌ Error: Memory allocation failed for buffer size %d\n", client_buf_size);
        close(fd);
        close(data_sock);
        return;
    }

    // Buffer for receiving ACKs; TFTP ACK packets are 4 bytes long
    uint8_t ack[4];
    socklen_t len = sizeof(data_client);
    int retries;  // Variable to track the number of retries per block

    // Set a timeout for recvfrom to prevent indefinite blocking (1-second timeout)
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(data_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Loop to read data from the file and send it in blocks to the client
    while ((bytes_read = read(fd, data_packet + 4, client_buf_size)) > 0) {
        // Prepare the TFTP DATA packet:
        // First 2 bytes: opcode for DATA, next 2 bytes: block number
        *(uint16_t *)data_packet = htons(OP_DATA);
        *(uint16_t *)(data_packet + 2) = htons(block);

        // Initialize the retry counter for this block
        retries = 3;
        while (retries--) {
            // Send the DATA packet (header + payload) to the client
            sendto(data_sock, data_packet, bytes_read + 4, 0, (struct sockaddr *)&data_client, sizeof(data_client));
            log_message(VERB_DEBUG, "📤 Sent DATA packet: Block=%d, Bytes=%zd (Retries left: %d)\n", 
                        block, bytes_read, retries);

            // Wait for the client's ACK for this block
            log_message(VERB_DEBUG, "🔄 Waiting for ACK for Block %d...\n", block);
            ssize_t recv_bytes = recvfrom(data_sock, ack, 4, 0, (struct sockaddr *)&data_client, &len);

            // Check if a valid ACK is received
            if (recv_bytes >= 4) {
                uint16_t received_opcode = ntohs(*(uint16_t *)ack);
                uint16_t received_block = ntohs(*(uint16_t *)(ack + 2));

                // Verify that the ACK is for the current block
                if (received_opcode == OP_ACK && received_block == block) {
                    log_message(VERB_DEBUG, "✅ ACK received for Block %d\n", block);
                    break;  // Proceed to the next block on successful ACK
                }

                // Log unexpected ACK details and continue retrying
                log_message(VERB_DEBUG, "⚠ Unexpected ACK for Block %d (Received Block=%d)\n", block, received_block);
            } else {
                // Log a warning if no ACK is received
                log_message(VERB_DEBUG, "⚠ No ACK received for Block %d, retransmitting...\n", block);
            }
        }

        // If all retries have been exhausted without a valid ACK, abort the transfer
        if (retries < 0) {
            log_message(VERB_ALWAYS, "❌ Error: Block %d lost after multiple attempts. Aborting transfer.\n", block);
            break;
        }

        // If the number of bytes read is less than the client's buffer size,
        // this is the final block of the file
        if (bytes_read < client_buf_size) {
            log_message(VERB_ALWAYS, "✅ Final Block Sent (Block %d, %zd bytes)\n", block, bytes_read);
            break;
        }

        // Increment block number for the next iteration
        block++;
    }

    // Log that the file transfer is complete
    log_message(VERB_ALWAYS, "✅ File transfer complete.\n");

    // Cleanup: close the file descriptor and data socket, free the allocated data packet memory,
    // and remove the client's buffer size information from any tracking structures
    close(fd);
    close(data_sock);
    free(data_packet);
    remove_client_buffer_size(client);
}

// Handle WRQ (Write Request)
void handle_wrq(int sock, struct sockaddr_in *client, socklen_t client_len, uint8_t *buffer, char *server_dir) {
    // Log that a Write Request (WRQ) is being handled.
    log_message(VERB_NORMAL, "🔒 Handling WRQ.\n");

    // Buffers to store the requested filename and its backup version.
    char filename[256], backup_filename[256];
    uint16_t client_buf_size;
    
    // Construct the full file path for the requested file (skip the opcode in buffer).
    snprintf(filename, sizeof(filename), "%s/%s", server_dir, buffer + 2);
    // Construct a backup filename by appending ".bak" to the original filename.
    snprintf(backup_filename, sizeof(backup_filename), "%s/%s.bak", server_dir, buffer + 2);
    log_message(VERB_NORMAL, "📂 Receiving file: %s\n", filename);

    // Open the backup file for writing; create it if it doesn't exist, and truncate it if it does.
    int fd = open(backup_filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        // If unable to open the file, send an error to the client and log the failure.
        send_error(sock, client, ERR_ACCESS_VIOLATION, "Unable to create file");
        perror("❌ Failed to open file for writing");
        return;
    }

    // Duplicate the client's address for data transfer.
    struct sockaddr_in data_client = *client;

    // Create a new UDP socket dedicated for data transfer.
    int data_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (data_sock < 0) {
        perror("❌ Failed to create data socket");
        close(fd);
        return;
    }

    // Bind the data socket to an ephemeral port (letting the OS choose a free port).
    struct sockaddr_in server_data_addr;
    memset(&server_data_addr, 0, sizeof(server_data_addr));
    server_data_addr.sin_family = AF_INET;
    server_data_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_data_addr.sin_port = htons(0);  // Use an ephemeral port

    if (bind(data_sock, (struct sockaddr *)&server_data_addr, sizeof(server_data_addr)) < 0) {
        perror("❌ Failed to bind data socket to ephemeral port");
        close(fd);
        close(data_sock);
        return;
    }

    // Retrieve and log the assigned ephemeral port for the data socket.
    socklen_t addr_len = sizeof(server_data_addr);
    getsockname(data_sock, (struct sockaddr *)&server_data_addr, &addr_len);
    uint16_t assigned_port = ntohs(server_data_addr.sin_port);
    log_message(VERB_NORMAL, "✅ Server bound to ephemeral port: %d\n", assigned_port);

    // Prepare an ACK packet for the WRQ (block 0) that includes the new ephemeral port.
    uint8_t ack_packet[6];
    *(uint16_t *)ack_packet = htons(OP_ACK);              // Set opcode to ACK.
    *(uint16_t *)(ack_packet + 2) = htons(0);               // Block number 0 for WRQ.
    *(uint16_t *)(ack_packet + 4) = htons(assigned_port);   // Inform the client of the new port.

    // Send the ACK to the client on the original socket.
    sendto(sock, ack_packet, 6, 0, (struct sockaddr *)client, client_len);
    log_message(VERB_NORMAL, "📤 Sent ACK for WRQ (Block=0), instructing client to use port %d\n", assigned_port);

    // Retrieve the client's preferred buffer size for the data transfer.
    client_buf_size = get_client_buffer_size(client);
    log_message(VERB_ALWAYS, "📥 Using buffer size: %d bytes for client %s:%d\n",
        client_buf_size, inet_ntoa(client->sin_addr), ntohs(client->sin_port));

    // Initialize the expected block number for incoming data packets.
    uint16_t expected_block = 1;
    // Allocate memory for receiving data packets (includes 4 bytes for the TFTP header).
    uint8_t *data_packet = (uint8_t *)malloc(client_buf_size + 4);
    int transfer_successful = 0; // Flag to indicate whether the transfer completes successfully.

    // Begin the loop to receive data packets.
    while (1) {
        socklen_t len = sizeof(data_client);
        log_message(VERB_DEBUG, "🔄 Waiting for data packet (Block %d)...\n", expected_block);
        // Receive a data packet from the client.
        ssize_t bytes_received = recvfrom(data_sock, data_packet, client_buf_size + 4, 0,
                                          (struct sockaddr *)&data_client, &len);

        // Ensure that the received packet is at least the size of the header.
        if (bytes_received < 4) {
            perror("❌ Error receiving data");
            break;
        }

        // Log the receipt of the data packet (excluding the 4-byte header).
        log_message(VERB_DEBUG, "📥 Received data packet (Block %d, %zd bytes)\n", expected_block, bytes_received - 4);

        // Extract opcode and block number from the received packet.
        uint16_t received_opcode = ntohs(*(uint16_t *)data_packet);
        uint16_t received_block = ntohs(*(uint16_t *)(data_packet + 2));
        uint16_t data_size = bytes_received - 4; // Determine the size of the data payload.

        // If the opcode is not for DATA, log an error and abort.
        if (received_opcode != OP_DATA) {
            log_message(VERB_ALWAYS, "❌ Unexpected opcode: %d\n", received_opcode);
            break;
        }

        // If a duplicate packet is received (block number less than expected), resend the ACK.
        if (received_block < expected_block) {
            log_message(VERB_DEBUG, "⚠ Duplicate Block=%d received, resending ACK\n", received_block);
            uint8_t ack[4];
            *(uint16_t *)ack = htons(OP_ACK);
            *(uint16_t *)(ack + 2) = htons(received_block);
            sendto(data_sock, ack, 4, 0, (struct sockaddr *)&data_client, len);
            continue;  // Skip writing duplicate data.
        }

        // If an out-of-order packet is received, log and ignore it.
        if (received_block > expected_block) {
            log_message(VERB_DEBUG, "❌ Out-of-order Block=%d received (expected %d), ignoring\n", received_block, expected_block);
            continue;
        }

        // Write the received data (after the header) to the backup file.
        write(fd, data_packet + 4, data_size);

        // Prepare and send an ACK for the received block.
        uint8_t ack[4];
        *(uint16_t *)ack = htons(OP_ACK);
        *(uint16_t *)(ack + 2) = htons(received_block);
        sendto(data_sock, ack, 4, 0, (struct sockaddr *)&data_client, len);
        log_message(VERB_NORMAL, "📤 Sent ACK for Block=%d\n", received_block);

        // If the received packet is smaller than the full buffer, it indicates the last packet.
        if (bytes_received < client_buf_size) {
            log_message(VERB_NORMAL, "✅ File transfer complete.\n");
            transfer_successful = 1;
            break;
        }

        // Increment the expected block number for the next packet.
        expected_block++;
    }

    // Clean up resources: close file and socket, free allocated memory, and clear buffer size info.
    close(fd);
    close(data_sock);
    free(data_packet);
    remove_client_buffer_size(client);

    // If the transfer was successful, copy the backup file to the actual file location.
    if (transfer_successful) {
        log_message(VERB_NORMAL, "📁 Copying backup to real file: %s -> %s\n", backup_filename, filename);
    
        int src_fd = open(backup_filename, O_RDONLY);
        if (src_fd < 0) {
            perror("❌ Error opening backup file for copying");
        } else {
            int dest_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (dest_fd < 0) {
                perror("❌ Error creating destination file");
            } else {
                char buffer[4096];  // 4KB buffer for copying file contents.
                ssize_t bytes_read, bytes_written;
    
                // Copy contents from the backup file to the final file.
                while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
                    bytes_written = write(dest_fd, buffer, bytes_read);
                    if (bytes_written != bytes_read) {
                        perror("❌ Error writing to destination file");
                        break;
                    }
                }
                close(dest_fd);
            }
            close(src_fd);
        }
    
    } else {
        // If the transfer failed, delete the incomplete backup file.
        if (unlink(backup_filename) == 0) {
            log_message(VERB_NORMAL, "⚠ Incomplete transfer, deleted %s\n", backup_filename);
        } else {
            perror("❌ Error deleting incomplete backup file");
        }
    
        // If the original file exists, create a new backup from it.
        if (access(filename, F_OK) == 0) {
            log_message(VERB_NORMAL, "📁 Creating a new backup from existing file: %s -> %s\n", filename, backup_filename);
    
            int src_fd = open(filename, O_RDONLY);
            if (src_fd < 0) {
                perror("❌ Error opening existing file for backup");
            } else {
                int dest_fd = open(backup_filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
                if (dest_fd < 0) {
                    perror("❌ Error creating backup file");
                } else {
                    char buffer[4096];  // 4KB buffer for file copying.
                    ssize_t bytes_read, bytes_written;
    
                    // Copy the data from the original file to the backup file.
                    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
                        bytes_written = write(dest_fd, buffer, bytes_read);
                        if (bytes_written != bytes_read) {
                            perror("❌ Error writing to backup file");
                            break;
                        }
                    }
                    close(dest_fd);
                }
                close(src_fd);
            }
        }
    }    
}

// Send error message to client
void send_error(int sock, struct sockaddr_in *client, uint16_t err_code, const char *message) {
    // Create a buffer for the error packet (maximum size 516 bytes as per TFTP spec)
    uint8_t error_packet[516];

    // Set the first 2 bytes to the TFTP error opcode (converted to network byte order)
    *(uint16_t *)error_packet = htons(OP_ERROR);

    // Set the next 2 bytes to the specific error code (converted to network byte order)
    *(uint16_t *)(error_packet + 2) = htons(err_code);

    // Copy the error message into the packet starting at byte 4
    // The message is expected to be a null-terminated string
    strcpy((char *)(error_packet + 4), message);

    // Calculate the total packet length: 2 bytes for opcode + 2 bytes for error code +
    // length of the message + 1 byte for the null terminator, then send the error packet
    sendto(sock, error_packet, strlen(message) + 5, 0, (struct sockaddr *)client, sizeof(*client));
}

// Logging function
void log_message(int verbosity, const char *format, ...) {
    // Only log the message if the provided verbosity is less than or equal to the global verbosity level.
    if (verbosity > verbose) return;

    // Initialize a variable argument list to process the variable arguments.
    va_list args;
    va_start(args, format);
    
    // Print the formatted message to stdout using the variable arguments.
    vprintf(format, args);
    
    // Clean up the variable argument list.
    va_end(args);
    
    // Flush stdout to ensure the message is output immediately.
    fflush(stdout);
}

void handle_md5_request(int sock, struct sockaddr_in *client, uint8_t *buffer, char *server_dir) {
    // Create a buffer to store the full file path.
    char filename[256];
    // Construct the full file path using the server directory and the filename from the request (skip the opcode).
    snprintf(filename, sizeof(filename), "%s/%s", server_dir, buffer + 2);

    // Log that an MD5 request has been received for the specified file.
    log_message(VERB_NORMAL, "MD5 request received for file: %s\n", filename);

    // Check if the file exists. If access() returns non-zero, the file is not accessible.
    if (access(filename, F_OK) != 0) {
        log_message(VERB_ALWAYS, "Error: File not found: %s\n", filename);
        // Send an error packet to the client indicating that the file was not found.
        send_error(sock, client, ERR_FILE_NOT_FOUND, "File not found");
        return;
    }

    // Buffer to store the computed MD5 hash (32 characters + null terminator).
    char md5_hash[33];
    // Compute the MD5 hash for the file. If the computation fails, log an error and notify the client.
    if (!compute_md5(filename, md5_hash)) {
        log_message(VERB_ALWAYS, "Error computing MD5 for: %s\n", filename);
        send_error(sock, client, ERR_UNDEFINED, "MD5 computation failed");
        return;
    }

    // Log the computed MD5 hash.
    log_message(VERB_ALWAYS, "MD5 computed: %s\n", md5_hash);
    // Send the MD5 hash to the client, including the null terminator.
    sendto(sock, md5_hash, strlen(md5_hash) + 1, 0, (struct sockaddr *)client, sizeof(*client));
}

void handle_md5_verify(int sock, struct sockaddr_in *client, socklen_t client_len, uint8_t *buffer, char *server_dir) {
    // Check that the received packet is large enough to be a valid MD5 verify request.
    if (client_len < 6) {  // Minimal MD5 request size (opcode, filename, and MD5 hash parts)
        log_message(VERB_ALWAYS, "⚠️ Ignored malformed MD5 request (size: %d)\n", client_len);
        return;
    }

    // Extract the opcode from the beginning of the packet.
    uint16_t received_opcode = ntohs(*(uint16_t *)buffer);
    
    // Log the opcode and packet size for debugging.
    log_message(VERB_DEBUG, "📥 MD5 request received: Opcode=%d, Size=%d\n", received_opcode, client_len);

    // Verify that the opcode matches the expected MD5 verification opcode.
    if (received_opcode != OP_MD5_VERIFY) {
        log_message(VERB_ALWAYS, "❌ Unexpected opcode: %d (Expected: %d)\n", received_opcode, OP_MD5_VERIFY);
        return;
    }

    // Construct the full file path using the server directory and filename from the request.
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/%s", server_dir, (char *)(buffer + 2));
    log_message(VERB_NORMAL, "📥 MD5 verification requested for file: %s\n", filename);

    // Check if the file exists; if not, send an error response to the client.
    if (access(filename, F_OK) != 0) {
        log_message(VERB_ALWAYS, "❌ Error: File not found: %s\n", filename);
        send_error(sock, client, ERR_FILE_NOT_FOUND, "File not found");
        return;
    }

    // Extract the expected MD5 hash from the packet.
    // The hash is expected to be at a fixed offset (258 bytes in) with a length of 32 bytes.
    char expected_md5[33];  // 32 characters plus null terminator
    memcpy(expected_md5, buffer + 258, 32);
    expected_md5[32] = '\0';  // Ensure the string is properly null-terminated

    log_message(VERB_VERBOSE, "✅ Client MD5:\t%s\n", expected_md5);

    // Compute the local MD5 hash for the specified file.
    char local_md5[33];
    if (compute_md5(filename, local_md5)) {
        log_message(VERB_VERBOSE, "💾 Local MD5:\t%s\n", local_md5);
        // Compare the computed MD5 hash with the one received from the client.
        if (strcmp(expected_md5, local_md5) == 0) {
            log_message(VERB_VERBOSE, "✅ MD5 Match!\n");
        } else {
            log_message(VERB_ALWAYS, "❌ MD5 Mismatch!\n");
        }
    } else {
        // If the MD5 computation fails, log an error.
        log_message(VERB_ALWAYS, "❌ Error computing local MD5\n");
    }

    // Prepare a one-byte response: 1 if the MD5 hashes match, 0 otherwise.
    uint8_t response = (strcmp(expected_md5, local_md5) == 0) ? 1 : 0;
    sendto(sock, &response, 1, 0, (struct sockaddr *)client, client_len);
    log_message(VERB_VERBOSE, "✅ MD5 result sent to client: %d\n", response);

    // After sending the result, clear out any extra packets that may be waiting.
    uint8_t extra_data[DEFAULT_BUFFER_SIZE + 4];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);

    while (1) {
        // Use MSG_DONTWAIT so recvfrom() returns immediately if there's no data.
        ssize_t extra_len = recvfrom(sock, extra_data, sizeof(extra_data), MSG_DONTWAIT, 
                                      (struct sockaddr *)&sender, &sender_len);

        if (extra_len < 0) {
            // If no more data is available (or if there's an error like EWOULDBLOCK/EAGAIN), exit the loop.
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                break;  // No more packets available, exit cleanly.
            }
            log_message(VERB_ALWAYS, "⚠️ recvfrom() error: %s\n", strerror(errno));
            break;
        }

        // Log any unexpected extra packets that were received.
        log_message(VERB_ALWAYS, "⚠️ Ignored unexpected packet from %s:%d (Size=%ld)\n",
                    inet_ntoa(sender.sin_addr), ntohs(sender.sin_port), extra_len);
    }
}

void handle_enc_rrq(int sock, struct sockaddr_in *client, uint8_t *buffer, char *server_dir) {
    // Create a buffer for the filename and declare a variable for the client's buffer size.
    char filename[256];
    uint16_t client_buf_size;
    
    // Construct the full file path by concatenating the server directory and the requested filename.
    // The filename in the buffer starts after the 2-byte opcode.
    snprintf(filename, sizeof(filename), "%s/%s", server_dir, buffer + 2);

    // Log the receipt of an encrypted RRQ along with the filename.
    log_message(VERB_ALWAYS, "🔒 Encrypted RRQ received. File: %s\n", filename);

    // Open the requested file in read-only mode.
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        // If the file cannot be opened, send an error back to the client and exit the function.
        send_error(sock, client, ERR_FILE_NOT_FOUND, "File not found");
        return;
    }

    // Copy the client's address for use with the data socket.
    struct sockaddr_in data_client = *client;
    
    // Create a new UDP socket for transferring the encrypted data.
    int data_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (data_sock < 0) {
        perror("❌ Failed to create data socket");
        close(fd);
        return;
    }

    // Set a timeout on the data socket for receiving ACKs (1-second timeout).
    struct timeval timeout;
    timeout.tv_sec = 1;      // 1 second timeout for ACKs
    timeout.tv_usec = 0;
    setsockopt(data_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Retrieve the client's preferred buffer size for data transfer.
    client_buf_size = get_client_buffer_size(client);
    log_message(VERB_ALWAYS, "📥 Using buffer size: %d bytes for client %s:%d\n",
                client_buf_size, inet_ntoa(client->sin_addr), ntohs(client->sin_port));

    // Initialize the AES initialization vector (IV) for encryption.
    uint8_t iv[AES_BLOCK_SIZE] = {0};  // IV must be shared between sender and receiver

    // Initialize block number (TFTP blocks start at 1) and declare variables.
    uint16_t block = 1;
    ssize_t bytes_read;
    
    // Allocate memory for a data packet which includes a 4-byte header plus the data payload.
    uint8_t *data_packet = (uint8_t *)malloc(client_buf_size + 4);
    
    // Buffer to store incoming ACK packets (4 bytes each).
    uint8_t ack[4];
    socklen_t len = sizeof(data_client);
    int retries = 3;  // Maximum number of retries per block

    // Main loop: read data from the file and send it in encrypted blocks.
    while ((bytes_read = read(fd, data_packet + 4, client_buf_size)) > 0) {
        // Encrypt the data portion of the packet using the AES IV.
        aes_encrypt(data_packet + 4, bytes_read, iv); // Encrypt data

        // Prepare the TFTP DATA packet header:
        // First 2 bytes: opcode for DATA; next 2 bytes: block number.
        *(uint16_t *)data_packet = htons(OP_DATA);
        *(uint16_t *)(data_packet + 2) = htons(block);

        // Reset the retry counter for this block.
        retries = 3;
        while (retries--) {
            // Send the encrypted data packet (header + payload) to the client.
            sendto(data_sock, data_packet, bytes_read + 4, 0, (struct sockaddr *)&data_client, sizeof(data_client));
            log_message(VERB_DEBUG, "📤 Sent Encrypted Block=%d (%zd bytes) to %s:%d (Retries left: %d)\n", 
                        block, bytes_read, inet_ntoa(data_client.sin_addr), ntohs(data_client.sin_port), retries);

            // Wait for the ACK from the client.
            log_message(VERB_DEBUG, "🔄 Waiting for ACK for Block %d...\n", block);
            ssize_t ack_received = recvfrom(data_sock, ack, 4, 0, (struct sockaddr *)&data_client, &len);

            // Verify if a valid ACK (of at least 4 bytes) is received.
            if (ack_received >= 4) {
                uint16_t received_opcode = ntohs(*(uint16_t *)ack);
                uint16_t received_block = ntohs(*(uint16_t *)(ack + 2));

                // If the ACK is valid for the current block, log and break out of the retry loop.
                if (received_opcode == OP_ACK && received_block == block) {
                    log_message(VERB_DEBUG, "✅ ACK received for Block %d\n", block);
                    break;  // ACK received, proceed to the next block.
                }

                // Log any unexpected ACK details.
                log_message(VERB_ALWAYS, "⚠ Unexpected ACK for Block %d (Received Block=%d)\n", block, received_block);
            } else {
                // Log a warning if no ACK was received.
                log_message(VERB_DEBUG, "⚠ No ACK received for Block %d, retransmitting...\n", block);
            }
        }

        // If all retries have been exhausted for this block, abort the transfer.
        if (retries < 0) {
            log_message(VERB_ALWAYS, "❌ Error: Block %d lost after multiple attempts. Aborting transfer.\n", block);
            break;
        }

        // If the last read returns fewer bytes than the client's buffer size,
        // this indicates the final block of the file.
        if (bytes_read < client_buf_size) {
            log_message(VERB_VERBOSE, "✅ Final Block Sent (Block %d, %zd bytes)\n", block, bytes_read);
            break;  // End of file reached.
        }

        // Increment the block counter for the next data packet.
        block++;
    }

    // Cleanup: close the file descriptor, close the data socket, free allocated memory,
    // and remove the client's buffer size info.
    close(fd);
    close(data_sock);
    free(data_packet);
    remove_client_buffer_size(client);
}

void handle_enc_wrq(int sock, struct sockaddr_in *client, socklen_t client_len, uint8_t *buffer, char *server_dir) {
    // Log the start of handling an encrypted Write Request (WRQ)
    log_message(VERB_NORMAL, "🔒 Handling encrypted WRQ.\n");

    // Buffers for the target filename and its backup version
    char filename[256], backup_filename[256];
    uint16_t client_buf_size;
    
    // Construct the full file path for the target file (skip the opcode in buffer)
    snprintf(filename, sizeof(filename), "%s/%s", server_dir, buffer + 2);
    // Construct the backup filename (appending ".bak")
    snprintf(backup_filename, sizeof(backup_filename), "%s/%s.bak", server_dir, buffer + 2);
    log_message(VERB_ALWAYS, "📂 Receiving encrypted file: %s\n", filename);

    // Open the backup file for writing (create if not exists, truncate if exists)
    int fd = open(backup_filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        // Send error if file creation fails and log the error
        send_error(sock, client, ERR_ACCESS_VIOLATION, "Unable to create file");
        perror("❌ Failed to open file for writing");
        return;
    }

    // Copy the client's address for use with the data socket
    struct sockaddr_in data_client = *client;

    // Create a new UDP socket for the data transfer
    int data_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (data_sock < 0) {
        perror("❌ Failed to create data socket");
        close(fd);
        return;
    }

    /** Bind data_sock to an ephemeral port **/
    struct sockaddr_in server_data_addr;
    memset(&server_data_addr, 0, sizeof(server_data_addr));
    server_data_addr.sin_family = AF_INET;
    server_data_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_data_addr.sin_port = htons(0);  // Use an ephemeral port chosen by the OS

    if (bind(data_sock, (struct sockaddr *)&server_data_addr, sizeof(server_data_addr)) < 0) {
        perror("❌ Failed to bind data socket to ephemeral port");
        close(fd);
        close(data_sock);
        return;
    }

    // Get and log the assigned ephemeral port for the data socket
    socklen_t addr_len = sizeof(server_data_addr);
    getsockname(data_sock, (struct sockaddr *)&server_data_addr, &addr_len);
    uint16_t assigned_port = ntohs(server_data_addr.sin_port);
    log_message(VERB_NORMAL, "✅ Server bound to ephemeral port: %d\n", assigned_port);

    /** Send ACK for WRQ request (block = 0) and include the ephemeral port **/
    uint8_t ack_packet[6];
    *(uint16_t *)ack_packet = htons(OP_ACK);             // Set opcode to ACK
    *(uint16_t *)(ack_packet + 2) = htons(0);              // Block number 0 for initial ACK
    *(uint16_t *)(ack_packet + 4) = htons(assigned_port);  // Inform client of the new data port

    // Send ACK on the original socket to instruct client to use the new ephemeral port
    sendto(sock, ack_packet, 6, 0, (struct sockaddr *)client, client_len);
    log_message(VERB_NORMAL, "📤 Sent ACK for WRQ (Block=0), instructing client to use port %d\n", assigned_port);

    // Retrieve the client's preferred buffer size and log it
    client_buf_size = get_client_buffer_size(client);
    log_message(VERB_ALWAYS, "📥 Using buffer size: %d bytes for client %s:%d\n",
        client_buf_size, inet_ntoa(client->sin_addr), ntohs(client->sin_port));

    // Initialize the AES Initialization Vector (IV) used for decryption (must match sender's IV)
    uint8_t iv[AES_BLOCK_SIZE] = {0};  // Using a consistent IV here

    // Set the expected block number for the incoming data packets (TFTP blocks start at 1)
    uint16_t expected_block = 1;
    uint8_t *data_packet;
    // Allocate memory for receiving data packets (client buffer size plus 4 bytes for header)
    data_packet = (uint8_t *)malloc(client_buf_size + 4);
    int transfer_successful = 0;  // Flag to indicate if the transfer completed successfully

    // Loop to receive data packets from the client
    while (1) {
        socklen_t len = sizeof(data_client);
        // Receive a data packet from the client on the data socket
        ssize_t bytes_received = recvfrom(data_sock, data_packet, client_buf_size + 4, 0,
                                          (struct sockaddr *)&data_client, &len);

        if (bytes_received < 4) {
            // If the received packet is too short, log an error and exit the loop
            perror("❌ Error receiving data");
            break;
        }

        // Extract opcode and block number from the packet header
        uint16_t received_opcode = ntohs(*(uint16_t *)data_packet);
        uint16_t received_block = ntohs(*(uint16_t *)(data_packet + 2));
        uint16_t data_size = bytes_received - 4;  // Determine the size of the data payload

        // Ensure the packet is a DATA packet; if not, log error and break
        if (received_opcode != OP_DATA) {
            log_message(VERB_ALWAYS, "❌ Unexpected opcode: %d\n", received_opcode);
            break;
        }

        // Handle duplicate packets by resending the ACK without writing duplicate data
        if (received_block < expected_block) {
            log_message(VERB_DEBUG, "⚠ Duplicate Block=%d received, resending ACK\n", received_block);
            uint8_t ack[4];
            *(uint16_t *)ack = htons(OP_ACK);
            *(uint16_t *)(ack + 2) = htons(received_block);
            sendto(data_sock, ack, 4, 0, (struct sockaddr *)&data_client, len);
            continue;
        }

        // Ignore out-of-order packets (if block is higher than expected)
        if (received_block > expected_block) {
            log_message(VERB_DEBUG, "❌ Out-of-order Block=%d received (expected %d), ignoring\n", received_block, expected_block);
            continue;
        }

        // Decrypt the received data payload using AES and the shared IV
        aes_decrypt(data_packet + 4, data_size, iv);

        // Write the decrypted data to the backup file
        write(fd, data_packet + 4, data_size);

        // Prepare and send an ACK for the received block
        uint8_t ack[4];
        *(uint16_t *)ack = htons(OP_ACK);
        *(uint16_t *)(ack + 2) = htons(received_block);
        sendto(data_sock, ack, 4, 0, (struct sockaddr *)&data_client, len);
        log_message(VERB_NORMAL, "📤 Sent ACK for Block=%d\n", received_block);

        // Check if this is the last packet (data size smaller than expected full block)
        // Note: For encrypted transfers, the condition might vary. Here we assume the last block is smaller.
        if (data_size < client_buf_size - 4) {
            log_message(VERB_NORMAL, "✅ Encrypted file transfer complete.\n");
            transfer_successful = 1;
            break;
        }

        // Increment the expected block number for the next iteration
        expected_block++;
    }

    // Clean up: close file and socket descriptors, free allocated memory, and remove client buffer size record
    close(fd);
    close(data_sock);
    free(data_packet);
    remove_client_buffer_size(client);

    // If the transfer was successful, copy the backup file to the final destination
    if (transfer_successful) {
        log_message(VERB_NORMAL, "📁 Copying backup to real file: %s -> %s\n", backup_filename, filename);
    
        int src_fd = open(backup_filename, O_RDONLY);
        if (src_fd < 0) {
            perror("❌ Error opening backup file for copying");
        } else {
            int dest_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (dest_fd < 0) {
                perror("❌ Error creating destination file");
            } else {
                char buffer[4096];  // 4KB temporary buffer for file copying
                ssize_t bytes_read, bytes_written;
    
                // Copy the backup file contents to the final file
                while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
                    bytes_written = write(dest_fd, buffer, bytes_read);
                    if (bytes_written != bytes_read) {
                        perror("❌ Error writing to destination file");
                        break;
                    }
                }
                close(dest_fd);
            }
            close(src_fd);
        }
    } else {
        // If the transfer failed, delete the incomplete backup file
        if (unlink(backup_filename) == 0) {
            log_message(VERB_NORMAL, "⚠ Incomplete transfer, deleted %s\n", backup_filename);
        } else {
            perror("❌ Error deleting incomplete backup file");
        }
    
        // If the original file exists, create a new backup from it
        if (access(filename, F_OK) == 0) {
            log_message(VERB_NORMAL, "📁 Creating a new backup from existing file: %s -> %s\n", filename, backup_filename);
    
            int src_fd = open(filename, O_RDONLY);
            if (src_fd < 0) {
                perror("❌ Error opening existing file for backup");
            } else {
                int dest_fd = open(backup_filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
                if (dest_fd < 0) {
                    perror("❌ Error creating backup file");
                } else {
                    char buffer[4096];  // 4KB temporary buffer for file copying
                    ssize_t bytes_read, bytes_written;
    
                    // Copy contents from the original file to the backup file
                    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
                        bytes_written = write(dest_fd, buffer, bytes_read);
                        if (bytes_written != bytes_read) {
                            perror("❌ Error writing to backup file");
                            break;
                        }
                    }
                    close(dest_fd);
                }
                close(src_fd);
            }
        }
    }
}

void handle_delete(int sock, struct sockaddr_in *client, socklen_t client_len, const char *server_dir, const char *filename) {
    // Buffers to hold the full paths for the target file and its backup version.
    char filepath[256], backup_filepath[256];

    // Construct the full file path by concatenating the server directory and the filename.
    snprintf(filepath, sizeof(filepath), "%s/%s", server_dir, filename);
    // Construct the backup file path by appending ".bak" to the filename.
    snprintf(backup_filepath, sizeof(backup_filepath), "%s/%s.bak", server_dir, filename);

    // Flags to track deletion status of the main file and backup file.
    int file_deleted = 0, backup_deleted = 0;

    // 🔥 Try deleting the main file if it exists.
    if (access(filepath, F_OK) == 0) {
        // If the file exists, attempt to delete it using unlink().
        if (unlink(filepath) == 0) {
            log_message(VERB_ALWAYS, "🗑 Deleted file: %s\n", filepath);
            file_deleted = 1;
        } else {
            // Log error if deletion fails.
            perror("❌ Error deleting file");
        }
    }

    // 🔥 Try deleting the backup file if it exists.
    if (access(backup_filepath, F_OK) == 0) {
        // Attempt to delete the backup file.
        if (unlink(backup_filepath) == 0) {
            log_message(VERB_NORMAL, "🗑 Deleted backup file: %s\n", backup_filepath);
            backup_deleted = 1;
        } else {
            // Log error if deletion of backup file fails.
            perror("❌ Error deleting backup file");
        }
    }

    // 📝 If neither the main file nor the backup file was deleted, log that no file was found.
    if (!file_deleted && !backup_deleted) {
        log_message(VERB_NORMAL, "⚠ No file to delete: %s or %s\n", filepath, backup_filepath);
    }

    // ✅ Prepare a DELETE ACK packet (using block number 0 for delete ACK).
    uint8_t ack_packet[4];
    *(uint16_t *)ack_packet = htons(OP_ACK);         // Set opcode to ACK.
    *(uint16_t *)(ack_packet + 2) = htons(0);          // Block number 0 for DELETE ACK.

    // Send the DELETE ACK packet back to the client.
    sendto(sock, ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)client, client_len);
    log_message(VERB_NORMAL, "📤 Sent DELETE ACK\n");
}

void handle_buffer_size_sync(int sock, struct sockaddr_in *client, socklen_t client_len, uint8_t *buffer) {
    // Extract the requested buffer size from the packet.
    // The size is located at an offset of 2 bytes (skipping the opcode).
    uint16_t requested_size = ntohs(*(uint16_t *)(buffer + 2));

    // Log the buffer size sync request, including the requested size and the client's IP and port.
    log_message(VERB_VERBOSE, "📥 Buffer size sync request: %d bytes from %s:%d\n",
           requested_size, inet_ntoa(client->sin_addr), ntohs(client->sin_port));

    // Validate the requested buffer size.
    // The valid range is between 512 bytes and 8192+4 bytes.
    if (requested_size < 512 || requested_size > 8192+4) {
        // Log an error and send an error packet if the requested size is invalid.
        log_message(VERB_ALWAYS, "❌ Invalid buffer size requested: %d\n", requested_size);
        send_error(sock, client, ERR_ILLEGAL_OP, "Invalid buffer size");
        return;
    }

    // Store the valid buffer size for the client in a hash table for future reference.
    store_client_buffer_size(client, requested_size);

    // Prepare an ACK packet for the buffer size sync.
    // The packet contains a 2-byte opcode (OP_ACK) and a 2-byte block number (0).
    uint8_t ack[4];
    *(uint16_t *)ack = htons(OP_ACK);
    *(uint16_t *)(ack + 2) = htons(0);

    // Send the ACK packet back to the client.
    sendto(sock, ack, 4, 0, (struct sockaddr *)client, client_len);
    
    // Log that the client's buffer size has been updated successfully.
    log_message(VERB_ALWAYS, "✅ Buffer size updated for client %s:%d -> %d bytes\n",
           inet_ntoa(client->sin_addr), ntohs(client->sin_port), requested_size);
}

void store_client_buffer_size(struct sockaddr_in *client, uint16_t buffer_size) {
    // Pointer to hold the client's buffer size entry from the hash table.
    ClientBufferEntry *entry;
    
    // Buffer to store the client's IP address in human-readable form.
    char client_ip[INET_ADDRSTRLEN];
    // Convert the client's IP address from binary form to a dotted-decimal string.
    inet_ntop(AF_INET, &client->sin_addr, client_ip, INET_ADDRSTRLEN);

    // Look up the client's entry in the hash table using the IP address as the key.
    HASH_FIND_STR(client_buffer_table, client_ip, entry);
    
    // If no entry exists, create a new one.
    if (!entry) {
        // Allocate memory for a new ClientBufferEntry.
        entry = (ClientBufferEntry *)malloc(sizeof(ClientBufferEntry));
        // Copy the client's IP address into the new entry's key field.
        strcpy(entry->client_ip, client_ip);
        // Add the new entry to the client_buffer_table using the client's IP as the key.
        HASH_ADD_STR(client_buffer_table, client_ip, entry);
    }
    
    // Update the client's buffer size in the entry.
    entry->buffer_size = buffer_size;
    
    // Log the successful storage of the client's buffer size.
    log_message(VERB_ALWAYS, "✅ Buffer size stored: %d bytes for client %s\n", buffer_size, client_ip);
}

// Retrieves the buffer size stored for a given client.
// If no size is stored, returns the DEFAULT_BUFFER_SIZE.
uint16_t get_client_buffer_size(struct sockaddr_in *client) {
    ClientBufferEntry *entry;
    char client_ip[INET_ADDRSTRLEN];

    // Convert the client's binary IP address into a human-readable string.
    inet_ntop(AF_INET, &client->sin_addr, client_ip, INET_ADDRSTRLEN);

    // Look up the client's entry in the hash table using their IP address.
    HASH_FIND_STR(client_buffer_table, client_ip, entry);

    // If found, return the stored buffer size; otherwise, return a default size.
    return (entry) ? entry->buffer_size : DEFAULT_BUFFER_SIZE;
}

// Frees all entries in the client buffer hash table.
void free_client_table() {
    ClientBufferEntry *entry, *tmp;

    // Iterate over each entry in the hash table.
    HASH_ITER(hh, client_buffer_table, entry, tmp) {
        // Delete the entry from the hash table.
        HASH_DEL(client_buffer_table, entry);
        // Free the memory allocated for the entry.
        free(entry);
    }
}

// Removes a client's buffer size entry from the hash table.
// A short delay is introduced to allow any pending MD5 requests to complete.
void remove_client_buffer_size(struct sockaddr_in *client) {
    ClientBufferEntry *entry;
    char client_ip[INET_ADDRSTRLEN];

    // Convert the client's IP address to a human-readable string.
    inet_ntop(AF_INET, &client->sin_addr, client_ip, INET_ADDRSTRLEN);

    // Wait a short period to ensure pending MD5 verification requests are processed.
    sleep(1);  // Small delay to allow MD5 verification

    // Find the client's entry in the hash table.
    HASH_FIND_STR(client_buffer_table, client_ip, entry);
    if (entry) {
        // Remove the entry from the hash table and free its memory.
        HASH_DEL(client_buffer_table, entry);
        free(entry);
        // Log that the client's buffer size entry has been removed.
        log_message(VERB_ALWAYS, "✅ Buffer size removed for client %s\n", client_ip);
    }
}
