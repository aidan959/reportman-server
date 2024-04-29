#define _POSIX_C_SOURCE 199309L // for POSIX timers
#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include "include/reportman_server.h"
#include "libs/include/reportman.h"
#include "libs/include/daemonize.h"
#include "libs/include/reportman_types.h"

typedef struct {
    int client_fd;
    pthread_t thread_id;
    char *username;
    char *groupname;
    unsigned long long bytes_transferred;
    bool active;
} client_info_t;

// List (or other structure) to hold client info
client_info_t *clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;



static daemon_arguments_t __exec_args = {
    .make_daemon = true,
    .daemon_port = REPORTMAND_BIND_PORT,
    .force = false,
    .close = false,
    .log_to_sys = false,
    .log_to_file = true};
int d_socket;
// --- MAYBE MOVE
static void __acquire_singleton(void);
static int __force_singleton(int singleton_result, unsigned short port);
// ---
void remove_client(int index);
int add_client(int fd);
void *monitor_clients(void *arg);
void send_json_response(int client_socket, const char *message, int status_code);
typedef struct client_handle_t {
    int client_fd;
    unsigned long long * client_id;
} client_handle_t;

char *get_username(u_int64_t uid);
char *get_groupname(u_int64_t gid);

static bool __client_request_close = false;

static void __handle_sigpipe(int sig);
static int __handle_clients(void);
static void __handle_client(void);

static void __clean_close(int signal_fd, int exit_code);
static int __kill_children(void);

pthread_mutex_t client_id_mutex = PTHREAD_MUTEX_INITIALIZER;


pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


int __force_singleton(int singleton_result, unsigned short port)
{
    syslog(LOG_WARNING, "Forcing reportman_server to start on port %d", port);
    printf("Forcing reportman_server to start on port %d\n", port);

    kill_pid(singleton_result);
    sleep(1);
    singleton_result = d_acquire_singleton(&d_socket, port);
    if (singleton_result != IS_SINGLETON)
    {
        fprintf(stderr, "Could not acquire singleton after force.");

        exit(EXIT_FAILURE);
    }
    return singleton_result;
}

static void __acquire_singleton(void)
{
    int singleton_result = d_acquire_singleton(&d_socket, __exec_args.daemon_port);
    if (__exec_args.close)
    {
        if (singleton_result == IS_SINGLETON)
        {
            printf("No reportman instance is running.\n");
        }
        else if (singleton_result > 0)
        {
            kill_pid(singleton_result);
            printf("reportmand (%d) closed successfully.\n", singleton_result);
        }
        exit(EXIT_SUCCESS);
    }

    switch (singleton_result)
    {
    case IS_SINGLETON:
        syslog(LOG_NOTICE, "reportmand started");
        break;
    case BIND_FAILED:
        syslog(LOG_ERR, "Could not bind to port %d", __exec_args.daemon_port);
        exit(EXIT_FAILURE);
    default:
        if (!__exec_args.force)
        {
            syslog(LOG_ERR, "Could not bind to port %d", __exec_args.daemon_port);
            exit(EXIT_FAILURE);
        }
        singleton_result = __force_singleton(singleton_result, __exec_args.daemon_port);
    }
}

int main(void)
{
    // ! TODO: Populate arguments
    __acquire_singleton();

    printf("Server got singleton on port: %u\n", __exec_args.daemon_port);
    fflush(stdout);
    return __handle_clients();
}

// ! REALLY REALLY IMPORTANT THAT EXECUTION HERE IS FULLY CONTROLLED
// TODO ABSTRACT THE METHODS HERE
/// @brief Listens to client and child processes
/// @param
/// @return Should exit
static int __handle_clients(void)
{

    struct sigaction sa;
    sa.sa_handler = __handle_sigpipe;
    sa.sa_flags = 0; // or SA_RESTART to auto-restart interrupted system calls
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGPIPE, &sa, NULL) == -1)
    {
        perror("sigaction");
        return 1;
    }

    struct pollfd fds[RMD_FD_POLL_MAX];
    int signal_fd;

    if ((signal_fd = r_initialize_signals()) < 0)
    {
        syslog(LOG_ERR, "Could not initialize signals");
        exit(EXIT_FAILURE);
    }

    fds[RMD_FD_POLL_SIGNAL].fd = signal_fd;
    fds[RMD_FD_POLL_SIGNAL].events = POLLIN;

    fds[RMD_FD_POLL_CLIENT].fd = d_socket;
    fds[RMD_FD_POLL_CLIENT].events = POLLIN;

    int poll_value;

    while (!__client_request_close)
    {
        poll_value = poll(fds, RMD_FD_POLL_MAX, -1);

        if (poll_value == -1)
        {
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "poll() failed: %s", strerror(errno));
            __kill_children();
            exit(EXIT_FAILURE);
        }
        if(fds[RMD_FD_POLL_SIGNAL].revents & POLLIN)
        {
            __clean_close(signal_fd, EXIT_SUCCESS);
        }
        if (fds[RMD_FD_POLL_CLIENT].revents & POLLIN)
        {
            __handle_client();
        }
    }
    __clean_close(signal_fd, EXIT_SUCCESS);
    return D_SUCCESS;
}

static void __clean_close(int signal_fd, int exit_code)
{
    __kill_children();

    close(signal_fd);

    close(d_socket);
    exit(exit_code);
}
void __handle_sigpipe(int sig)
{
    syslog(LOG_ERR, "Pipe closed. (%d) Process closed unexpectedly.", sig);
}
/// @brief Kills all child processes of this parent one
/// @param
static int __kill_children(void)
{

    kill(0, SIGTERM);

    int status;
    waitpid(0, &status, 0);
    return status;
}

void *handle_client(void *arg)
{
    client_handle_t* client_handle = (client_handle_t *) arg;
    char buffer[COMMUNICATION_BUFFER_SIZE];
    FILE *file = NULL;
    int client_socket = client_handle->client_fd;

    pthread_mutex_lock(&clients_mutex);
    int client_index = add_client(client_socket);
    pthread_mutex_unlock(&clients_mutex);

    if (client_index == -1) {
        send_json_response(client_socket, "Max client limit reached.", COMMAND_ERROR);
        goto close_socket;
    }

    pthread_mutex_lock(&client_id_mutex);
    client_handle->client_id++;
    unsigned long long client_id = *(client_handle->client_id);
    pthread_mutex_unlock(&client_id_mutex);
    // Receive JSON data from client
    ssize_t bytes_received = recv(client_socket, buffer, COMMUNICATION_BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("Error receiving JSON data");
        goto remove_client_close;
    }
    
    buffer[bytes_received] = '\0';

    printf("Client (%llu): Received JSON data: \n%s\n", client_id, buffer);
    
    // Parse JSON data
    json_object *jobj = json_tokener_parse(buffer);
    if (jobj == NULL) {
        perror("Error parsing JSON data");
        goto remove_client_close;

        exit(EXIT_FAILURE);
    }

    // Extract user ID and group ID from JSON object
    json_object *uid_obj;
    json_object *gid_obj;
    json_object *file_size_obj;
    json_object *file_path_obj;
    json_object *department_obj;
    json_object *file_name_obj;
    if (!json_object_object_get_ex(jobj, "user_id", &uid_obj) ||
        !json_object_object_get_ex(jobj, "group_id", &gid_obj) ||
        !json_object_object_get_ex(jobj, "file_size", &file_size_obj) ||
        !json_object_object_get_ex(jobj, "file_name", &file_name_obj)||
        !json_object_object_get_ex(jobj, "department", &department_obj)||
        !json_object_object_get_ex(jobj, "file_path", &file_path_obj)
        ){

        perror("Error extracting user_id or group_id from JSON object");
        exit(EXIT_FAILURE);
    }

    u_int64_t uid = json_object_get_uint64(uid_obj);
    u_int64_t gid = json_object_get_uint64(gid_obj);
    u_int64_t file_size = json_object_get_uint64(file_size_obj);
    const char *file_path = json_object_get_string(file_path_obj);
    const char *file_name = json_object_get_string(file_name_obj);
    const char *department = json_object_get_string(department_obj);

    // Get user and group names
    char *username = get_username(uid);
    char *groupname = get_groupname(gid);

    if (username != NULL && groupname != NULL) {
        printf("Received user_id: %ld (%s)\n", uid, username);
        printf("Received group_id: %ld (%s)\n", gid, groupname);
    } else {

        printf("Error: Unable to retrieve user or group information.\n");
        send_json_response(client_socket, "Error creating directory.", COMMAND_ERROR);
        goto close_json;
    }
    printf("Received file_size: %ld\n", file_size);
    printf("Received file_name: %s\n", file_name);
    printf("Received file_path: %s\n", file_path);
    printf("Received department: %s\n", department);

    u_int64_t total_bytes_received = 0;

    char * new_filename = join_paths(department, file_name);
    

    int create_directory = create_directory_if_not_exists(department, uid, gid);

    switch (create_directory) {
        case COULD_NOT_CREATE_DIRECTORY:
            send_json_response(client_socket, "Error creating directory.", COMMAND_ERROR);
            close(client_socket);
            pthread_exit(NULL);
            break;
        case USER_NOT_IN_DIRECTORY_GROUP:
            send_json_response(client_socket, "User not in directory group.", COMMAND_ERROR);
            close(client_socket);
            pthread_exit(NULL);
            break;
        case COULD_NOT_CHOWN_DIRECTORY:
            send_json_response(client_socket, "Server could not change owner of created directory.", COMMAND_ERROR);
            close(client_socket);
            pthread_exit(NULL);
            break;
        case D_SUCCESS:
        default:
            break;

    }

    // Open file for writing
    printf("Opening file (%s) for writing.\n", new_filename);
    file = fopen(new_filename, "wb");
    if (file == NULL) {
        perror("Error opening file");
        send_json_response(client_socket, "Error opening file", COMMAND_ERROR);
        goto close_json;
    }
    // TODO CONFRIM THAT WE CAN GO AHEAD 
    // SEND JSON THAT CONTAINS ERROR MESSAGE OR ACK
        // After successfully processing the file
    send_json_response(client_socket, "ACK", COMMAND_SUCCESSFUL);


    // Receive file content
    printf("Receiving file content.\n");
    while (total_bytes_received < file_size) {

        bytes_received = recv(client_socket, buffer, COMMUNICATION_BUFFER_SIZE, 0);
        if (bytes_received < 0) {
            goto close_json;

        } else if (bytes_received == 0) {
            break;
        }
        total_bytes_received += (u_int64_t) bytes_received;
        size_t written = fwrite(buffer, 1, (size_t)bytes_received, file);
        if (written < (size_t)bytes_received) {
            perror("File write failed");
            goto close_json;
        }
    }
    printf("File received.\n");
    if (bytes_received < 0) {
        perror("Error receiving file content");
        goto close_json;

    }
    // After successfully processing the file
    json_object_put(jobj);

    jobj = json_object_new_object();
    json_object_object_add(jobj, "bytes_read", json_object_new_uint64(total_bytes_received));
    // Serialize JSON object to string
    const char *json_str = json_object_to_json_string(jobj);
    if (json_str == NULL)
    {
        perror("Error serializing JSON object");
        goto close_json;
    }
    if(strlen(json_str) > COMMUNICATION_BUFFER_SIZE){
        perror("JSON object too large, communication buffer will need to be increased.");
        goto close_json;

    }
    printf("Sending JSON data to client.\n");
    
    if (send(client_socket, json_str, strlen(json_str), 0) < 0)
    {
        perror("Error sending JSON data");
        goto close_json;
    }
    // Clean up
    close_json:
    json_object_put(jobj);
    if (file != NULL)
        fclose(file);
    remove_client_close:
    pthread_mutex_lock(&clients_mutex);
    remove_client(client_index);
    pthread_mutex_unlock(&clients_mutex);
    close_socket:
    close(client_socket);
    pthread_exit(NULL);
}

static void __handle_client(void)
{
    static unsigned long long client_id = 0;

    struct sockaddr_in client_addr;


    socklen_t client_addr_len = sizeof(client_addr);

    int client_fd = accept(d_socket, (struct sockaddr *)&client_addr, &client_addr_len);

    if (client_fd < 0)
    {
        if (errno == EINTR)
            return;
        syslog(LOG_ALERT, "accept() failed (unexpected): %s", strerror(errno));
        return;
    }
    printf("Client connected\n");
    fd_set readfds;
    struct timeval tv;

    tv.tv_sec = 10;
    tv.tv_usec = 0;

    FD_ZERO(&readfds);
    FD_SET(client_fd, &readfds);
    int retval = select(client_fd + 1, &readfds, NULL, NULL, &tv);
    if (retval == -1)
    {
        syslog(LOG_ERR, "select() failed: %s", strerror(errno));
    }
    else if (retval == 0)
    {
        // No data received within timeout, close the connection
        printf("Timeout reached. Closing connection.\n");
        char timeout_msg[] = "Timeout reached. Closing connection.";
        write(client_fd, timeout_msg, sizeof(timeout_msg));
        close(client_fd);
        return;
    }
    client_handle_t client_handle = {client_fd, &client_id};
    pthread_t thread_id;
    if(pthread_create(&thread_id, NULL, handle_client, (void *)&client_handle) != 0){
        perror("Error creating thread");
        close(client_fd);
    } 
}

char *get_username(u_int64_t uid) {
    struct passwd *pw = getpwuid((uid_t)uid);
    return (pw != NULL) ? pw->pw_name : NULL;
}

char *get_groupname(u_int64_t gid) {
    struct group *gr = getgrgid((gid_t)gid);
    return (gr != NULL) ? gr->gr_name : NULL;
}



/**
 * Check if a user has write permission on a given directory.
 *
 * @param directory Path to the directory.
 * @param user_id User ID of the client.
 * @param group_id Group ID of the client.
 * @return true if the user has write permission, false otherwise.
 */
bool has_write_permission(const char *directory, uid_t user_id, gid_t group_id) {
    struct stat statbuf;

    if (stat(directory, &statbuf) == -1) {
        perror("Failed to get directory stats");
        return false;
    }

    if (statbuf.st_uid == user_id) {
        return (statbuf.st_mode & S_IWUSR) != 0;
    }

    if (statbuf.st_gid == group_id) {
        return (statbuf.st_mode & S_IWGRP) != 0;
    }

    return (statbuf.st_mode & S_IWOTH) != 0;
}


void send_json_response(int client_socket, const char *message, int status_code) {
    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "status_code", json_object_new_int(status_code));
    json_object_object_add(jobj, "message", json_object_new_string(message));
    const char *json_str = json_object_to_json_string(jobj);
    if (json_str == NULL) {
        perror("Error serializing JSON object");
        exit(EXIT_FAILURE);
    }
    if (send(client_socket, json_str, strlen(json_str), 0) < 0) {
        perror("Error sending JSON data");
        exit(EXIT_FAILURE);
    }
    json_object_put(jobj);
}


int add_client(int fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == NULL) {
            clients[i] = malloc(sizeof(client_info_t));
            clients[i]->client_fd = fd;
            clients[i]->bytes_transferred = 0;
            clients[i]->active = true;
            return i;
        }
    }
    return -1;
}


void remove_client(int index) {
    if (clients[index] != NULL) {
        free(clients[index]);
        clients[index] = NULL;
    }
}

void *monitor_clients(void *arg) {
    while (true) {
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i] != NULL && clients[i]->active) {
                printf("Client %d: %llu bytes transferred, User: %s, Group: %s\n",
                       clients[i]->client_fd, clients[i]->bytes_transferred,
                       clients[i]->username, clients[i]->groupname);
            }
        }
        pthread_mutex_unlock(&clients_mutex);
        sleep(1);  // Update interval
    }
    return NULL;
}