#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>
#include <json-c/json.h>
#include "include/reportman_client.h"
#include "libs/include/reportman.h"
void print_progress(size_t received, size_t total);


int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <server_ip> <file_to_upload>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];
    char *file_path = argv[2];

    int client_socket;
    struct sockaddr_in server_addr;
    FILE *file;
    char buffer[COMMUNICATION_BUFFER_SIZE];
    size_t bytes_read;

    // Create socket
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Initialize server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(REPORTMAND_BIND_PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    printf("Connecting to server\n");
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Open file for reading
    printf("Opening file (%s) for reading.\n", file_path);
    file = fopen(file_path, "rb");
    if (file == NULL)
    {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    size_t file_size = (size_t)ftell(file);
    rewind(file);
    // Get user ID and group ID
    uid_t uid = getuid();
    gid_t gid = getgid();

    // Create JSON object
    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "user_id", json_object_new_uint64(uid));
    json_object_object_add(jobj, "group_id", json_object_new_uint64(gid));
    json_object_object_add(jobj, "file_size", json_object_new_uint64(file_size));
    json_object_object_add(jobj, "file_path", json_object_new_string(file_path));

    // Serialize JSON object to string
    const char *json_str = json_object_to_json_string(jobj);
    if (json_str == NULL)
    {
        perror("Error serializing JSON object");
        exit(EXIT_FAILURE);
    }
    if(strlen(json_str) > COMMUNICATION_BUFFER_SIZE){
        perror("JSON object too large, communication buffer will need to be increased.");
        exit(EXIT_FAILURE);
    }
    printf("Sending JSON data to server.\n");
    // Send JSON data to server
    if (send(client_socket, json_str, strlen(json_str), 0) < 0)
    {
        perror("Error sending JSON data");
        exit(EXIT_FAILURE);
    }

    // Clean up
    json_object_put(jobj);

    size_t total_bytes_received = 0;
    // Read and send file content
    printf("Reading and sending file content.\n");
    while ((bytes_read = fread(buffer, 1, COMMUNICATION_BUFFER_SIZE, file)) > 0) {

        if (send(client_socket, buffer, bytes_read, 0) < 0) {
            perror("Error sending file content");
            exit(EXIT_FAILURE);
        }
        total_bytes_received += (size_t)bytes_read;
        print_progress(total_bytes_received, file_size);
    }
    // send end of file
    printf("Sending end of file marker.\n");
    send(client_socket, "", 0, 0);
    if (bytes_read == 0)
    {
        perror("Error reading file");
        exit(EXIT_FAILURE);
    }
    ssize_t net_bytes_read = 0;
    // Wait for acknowledgment from the server
    printf("Waiting for acknowledegement.\n");
    while (1)
    {
        net_bytes_read = recv(client_socket, buffer, COMMUNICATION_BUFFER_SIZE, 0);
        if (net_bytes_read < 0)
        {
            perror("Error receiving acknowledgment");
            exit(EXIT_FAILURE);
        }
        else if (net_bytes_read == 0)
        {
            // Connection closed by server
            printf("Server closed connection.\n");
            break;
        }
        else
        {
            printf("Received acknowledegement: %s\n", buffer);
            if (strcmp(buffer, "ACK") == 0)
            {
                // Acknowledgment received, exit loop
                printf("Acknowledgment received. File upload complete.\n");
                break;
            }
        }
    }
    fclose(file);
    close(client_socket);
    return 0;
}




void print_progress(size_t received, size_t total) {
    const int bar_width = 50;
    float progress = (float)received / (float)total;
    int pos = (int)((float)bar_width * progress);

    printf("%3d%% [", (int)(progress * 100));
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("]\r");  
    if(received == total) printf("\n");
    fflush(stdout);

}