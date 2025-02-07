#include "md5_utils.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define TFTP_PORT 69
#define BUFFER_SIZE 516  // 512 (Data) + 4 (Header)

// TFTP Opcodes
#define OP_RRQ  1
#define OP_WRQ  2
#define OP_DATA 3
#define OP_ACK  4
#define OP_ERROR 5

void handle_client(int sock, struct sockaddr_in *client_addr, socklen_t client_len, u_int8_t *buffer);

int main() {
    int sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    u_int8_t buffer[BUFFER_SIZE];

    // Create UDP socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind to port 69
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TFTP_PORT);
    
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("TFTP Server listening on port %d...\n", TFTP_PORT);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);

        printf("Received request from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        handle_client(sock, &client_addr, client_len, buffer);
    }

    close(sock);
    return 0;
}

void handle_client(int sock, struct sockaddr_in *client_addr, socklen_t client_len, u_int8_t *buffer) {
    int opcode = ntohs(*(short *)buffer);

    printf("Socket: %d", sock);

    switch (opcode)
    {
        case OP_RRQ:
            printf("Read Request (RRQ) received.\n");
            // Implement file sending logic here
            break;
        case OP_WRQ:
            printf("Write Request (WRQ) received.\n");
            // Implement file receiving logic here
            break;
        default:
            printf("Unknown request received.\n");
            break;
    }
}