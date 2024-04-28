#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 7770
#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <server_ip> <file_to_upload>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];
    char *file_path = argv[2];

    int client_socket;
    struct sockaddr_in server_addr;
    FILE *file;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // Create socket
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Initialize server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Send file name
    if (send(client_socket, file_path, strlen(file_path), 0) < 0) {
        perror("Error sending file name");
        exit(EXIT_FAILURE);
    }

    // Open file for reading
    file = fopen(file_path, "rb");
    if (file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    // Read and send file content
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (send(client_socket, buffer, bytes_read, 0) < 0) {
            perror("Error sending file content");
            exit(EXIT_FAILURE);
        }
    }

    if (bytes_read < 0) {
        perror("Error reading file");
        exit(EXIT_FAILURE);
    }

    fclose(file);
    close(client_socket);
    return 0;
}