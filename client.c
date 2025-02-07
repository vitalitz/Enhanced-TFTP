#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define TFTP_PORT 69
#define BUFFER_SIZE 516

#define OP_RRQ  1
#define OP_WRQ  2
#define OP_DATA 3
#define OP_ACK  4
#define OP_ERROR 5

void send_rrq(int sock, struct sockaddr_in *server_addr, const char *filename);

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <server_ip> <filename>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int sock;
    struct sockaddr_in server_addr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TFTP_PORT);
    inet_pton(AF_INET, argv[1], &server_addr.sin_addr);

    send_rrq(sock, &server_addr, argv[2]);

    close(sock);
    return 0;
}

void send_rrq(int sock, struct sockaddr_in *server_addr, const char *filename) {
    char buffer[BUFFER_SIZE];
    int len = 2 + strlen(filename) + 1 + strlen("octet") + 1;  // Opcode + Filename + Mode

    memset(buffer, 0, BUFFER_SIZE);
    *(short *)buffer = htons(OP_RRQ);
    strcpy(buffer + 2, filename);
    strcpy(buffer + 2 + strlen(filename) + 1, "octet");

    sendto(sock, buffer, len, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));
    printf("RRQ for %s sent.\n", filename);
}