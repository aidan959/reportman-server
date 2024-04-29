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
#include <json-c/json.h>
#include "include/reportman_server.h"
#include "libs/include/reportman.h"
#include "libs/include/daemonize.h"
#include "libs/include/reportman_types.h"

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


char *get_username(u_int64_t uid);
char *get_groupname(u_int64_t gid);

static bool __client_request_close = false;

static void __handle_sigpipe(int sig);
static int __handle_clients(void);
static void __handle_client(void);

static void __clean_close(int signal_fd, int exit_code);
static int __kill_children(void);

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
    int client_socket = *((int *)arg);
    char buffer[COMMUNICATION_BUFFER_SIZE];
    FILE *file;

    // Receive JSON data from client
    ssize_t bytes_received = recv(client_socket, buffer, COMMUNICATION_BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("Error receiving JSON data");
        exit(EXIT_FAILURE);
    }
    printf("Received JSON data\n");
    // Null-terminate received data
    buffer[bytes_received] = '\0';

    // Parse JSON data
    json_object *jobj = json_tokener_parse(buffer);
    if (jobj == NULL) {
        perror("Error parsing JSON data");
        exit(EXIT_FAILURE);
    }

    // Extract user ID and group ID from JSON object
    json_object *uid_obj, *gid_obj, *file_size_obj, *file_path_obj;
    if (!json_object_object_get_ex(jobj, "user_id", &uid_obj) ||
        !json_object_object_get_ex(jobj, "group_id", &gid_obj) ||
        !json_object_object_get_ex(jobj, "file_size", &file_size_obj) ||
        !json_object_object_get_ex(jobj, "file_path", &file_path_obj)){
        perror("Error extracting user_id or group_id from JSON object");
        exit(EXIT_FAILURE);
    }

    u_int64_t uid = json_object_get_uint64(uid_obj);
    u_int64_t gid = json_object_get_uint64(gid_obj);
    u_int64_t file_size = json_object_get_uint64(file_size_obj);
    const char *file_path = json_object_get_string(file_path_obj);

    // Get user and group names
    char *username = get_username(uid);
    char *groupname = get_groupname(gid);

    if (username != NULL && groupname != NULL) {
        printf("Received user_id: %ld (%s)\n", uid, username);
        printf("Received group_id: %ld (%s)\n", gid, groupname);
    } else {
        printf("Error: Unable to retrieve user or group information.\n");
    }
    
    printf("Received file_size: %ld\n", file_size);
    printf("Received file_path: %s\n", file_path);

    long file_size_received = 0;
    long total_bytes_received = 0;

    char new_filename[COMMUNICATION_BUFFER_SIZE] = "./output/";
    strcat(new_filename, file_path);


    // Open file for writing
    printf("Opening file (%s) for writing.\n", new_filename);
    file = fopen(new_filename, "wb");
    if (file == NULL) {
        perror("Error opening file");
        close(client_socket);
        pthread_exit(NULL);
    }

    // Receive file content
    printf("Receiving file content.\n");
    while (total_bytes_received < file_size_received) {
        printf("recv'ing data.\n");
        bytes_received = recv(client_socket, buffer, COMMUNICATION_BUFFER_SIZE, 0);
        if (bytes_received < 0) {
            perror("Error receiving file content");
            exit(EXIT_FAILURE);
        } else if (bytes_received == 0) {
            printf("Connection closed by client.\n");
            break;
        }
        total_bytes_received += bytes_received;
        printf("Received bytes (%ld/%ld).\n", total_bytes_received, file_size_received);
        size_t written = fwrite(buffer, 1, (size_t)bytes_received, file);
        if (written < (size_t)bytes_received) {
            perror("File write failed");
            exit(EXIT_FAILURE);
        }
    }
    printf("File received.\n");
    if (bytes_received < 0) {
        perror("Error receiving file content");
    }
    // After successfully processing the file
    json_object_put(jobj);
    fclose(file);
    close(client_socket);
    pthread_exit(NULL);
}

static void __handle_client(void)
{
    static unsigned long long client_id = 0;
    char buffer[COMMUNICATION_BUFFER_SIZE];

    struct sockaddr_in client_addr;
    pthread_t thread_id;

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

    int retval;
    while ((retval = select(client_fd + 1, &readfds, NULL, NULL, &tv)))
    {
        handle_client((void *)&client_fd);
        continue;
        ssize_t len = read(client_fd, buffer, COMMUNICATION_BUFFER_SIZE - 1);
        if (len > 0)
        {
            syslog(LOG_NOTICE, "Client %llu has connected to dameon.", client_id);
            printf("Client %llu has connected to dameon.\n", client_id);
            // FD_ISSET(0, &readfds) will be true.
            buffer[len] = '\0';
            syslog(LOG_NOTICE, "Received command %s from client %llu\n", buffer, client_id);
            handle_client((void *)&client_fd);
            //pthread_create(&thread_id, NULL, handle_client, (void *)&client_fd);
            write(client_fd, "", 0);
        }
        else if (len == 0)
        {
            syslog(LOG_NOTICE, "Client %llu closed their connection.", client_id);
            break;
        }
        else if (len < 0)
        {
            syslog(LOG_ERR, "read failed: %s", strerror(errno));
        }
    }
    if (retval == -1)
    {
        syslog(LOG_ERR, "select() failed: %s", strerror(errno));
    }
    else
    {
        // no comms made in 10 seconds - lets close prematurely so another client can connect
        char timeout_msg[] = "Timeout reached. Closing connection.";
        write(client_fd, timeout_msg, sizeof(timeout_msg));
    }

    close(client_fd); // Close the client socket
    client_id++;
}





char *get_username(u_int64_t uid) {
    struct passwd *pw = getpwuid((uid_t)uid);
    return (pw != NULL) ? pw->pw_name : NULL;
}

char *get_groupname(u_int64_t gid) {
    struct group *gr = getgrgid((gid_t)gid);
    return (gr != NULL) ? gr->gr_name : NULL;
}