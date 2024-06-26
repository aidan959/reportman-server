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
int get_json_response( int client_socket, char *buffer, char ** message );

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("Usage: %s <server_ip> <file_to_upload> <destination_department>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];
    char *input_file = argv[2];
    char *department = argv[3];


    char *file_name;
    char *file_path;

    split_path(input_file, &file_path, &file_name);

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
    printf("Opening file (%s) for reading.\n", input_file);
    file = fopen(input_file, "rb");
    if (file == NULL)
    {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    printf("Getting file size.\n");
    // Get file size
    fseek(file, 0, SEEK_END);
    size_t file_size = (size_t)ftell(file);
    rewind(file);
    // Get user ID and group ID
    uid_t uid = getuid();
    gid_t gid = getgid();
    printf("Create JSON object.\n");

    // Create JSON object
    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "user_id", json_object_new_uint64(uid));
    json_object_object_add(jobj, "group_id", json_object_new_uint64(gid));
    json_object_object_add(jobj, "file_size", json_object_new_uint64(file_size));
    json_object_object_add(jobj, "file_name", json_object_new_string(file_name));
    json_object_object_add(jobj, "file_path", json_object_new_string(file_path));
    json_object_object_add(jobj, "department", json_object_new_string(department));

    printf("Serializing JSON object.\n");
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
    printf("JSON data: \n%s\n", json_str);

    printf("Sending JSON data to server.\n");
    // Send JSON data to server
    if (send(client_socket, json_str, strlen(json_str), 0) < 0)
    {
        perror("Error sending JSON data");
        exit(EXIT_FAILURE);
    }

    // Clean up
    json_object_put(jobj);

    char * message = malloc(COMMUNICATION_BUFFER_SIZE); 
    if (get_json_response(client_socket, buffer, &message ) != D_SUCCESS) {
        printf("Error sending file information to server: %s\n", message);
        exit(EXIT_FAILURE);
    }

    if (strcmp(message, "ACK") != 0)
    {
        printf("Unexpected server response: %s\n", buffer);
        exit(EXIT_FAILURE);
    }
    free(message);

    size_t total_bytes_received = 0;
    // Read and send file content
    printf("Reading and sending file content.\n");
    while ((bytes_read = fread(buffer, 1, COMMUNICATION_BUFFER_SIZE, file)) > 0) {

        if (send(client_socket, buffer, bytes_read, 0) < 0) {
            perror("\nError sending file content");
            exit(EXIT_FAILURE);
        }
        total_bytes_received += (size_t)bytes_read;
        print_progress(total_bytes_received, file_size);
    }
 
    // Receive JSON data from client
    ssize_t bytes_received = recv(client_socket, buffer, COMMUNICATION_BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("Error receiving JSON data");
        exit(EXIT_FAILURE);
    }
    
    buffer[bytes_received] = '\0';

    printf("Received JSON data: \n%s\n", buffer);
    
    // Parse JSON data
    jobj = json_tokener_parse(buffer);
    if (jobj == NULL) {
        perror("Error parsing JSON data");
        exit(EXIT_FAILURE);
    }

    // Extract user ID and group ID from JSON object
    json_object *bytes_read_obj = NULL;
    if (!json_object_object_get_ex(jobj, "bytes_read", &bytes_read_obj)){
         perror("Error extracting bytes_read from JSON object");
        exit(EXIT_FAILURE);
    }

    u_int64_t net_bytes_read = json_object_get_uint64(bytes_read_obj);
    printf("File transfer was successful. Bytes read: %lu\n", net_bytes_read);
    json_object_put(jobj);
    
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


int get_json_response( int client_socket, char *buffer, char ** message ){
    if (message == NULL) 
    {
        printf("Message must be allocated before calling get_json_response\n");
        exit(EXIT_FAILURE);
    }
    ssize_t bytes_received = recv(client_socket, buffer, COMMUNICATION_BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("Error receiving JSON data");
        exit(EXIT_FAILURE);
    }
    
    buffer[bytes_received] = '\0';
    printf("Received JSON data: \n%s\n", buffer);
    json_object * jobj;
    // Parse JSON data
    jobj = json_tokener_parse(buffer);
    if (jobj == NULL) {
        perror("Error parsing JSON data");
        exit(EXIT_FAILURE);
    }
    json_object *message_obj;
    json_object *status_obj;
    if( !json_object_object_get_ex(jobj, "message", &message_obj) ||
        !json_object_object_get_ex(jobj, "status_code", &status_obj)) {
            perror("Error extracting message or status_code from JSON object");
            exit(EXIT_FAILURE);
    }
    *message = strdup(json_object_get_string(message_obj));
    int status_code = json_object_get_int(status_obj);
    json_object_put(jobj);
    return status_code;
}