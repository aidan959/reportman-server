#define _POSIX_C_SOURCE 199309L // for POSIX timers
#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <sys/signalfd.h>



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
    .log_to_file = true
};
int d_socket;
// --- MAYBE MOVE
static void __acquire_singleton(void);
static int __force_singleton(int singleton_result, unsigned short port);
// ---
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

int main (void) {
    // ! TODO: Populate arguments
    __acquire_singleton();

    printf("Server got singleton on port: %u", __exec_args.daemon_port);
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

    if ((signal_fd = r_cinitialize_signals()) < 0)
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
        if (fds[RMD_FD_POLL_SIGNAL].revents & POLLIN)
        {
            struct signalfd_siginfo fdsi;

            // signal size received from read was incorrect
            ssize_t read_size;
            if ((read_size = read(fds[RMD_FD_POLL_SIGNAL].fd, &fdsi, sizeof(fdsi))) != sizeof(fdsi))
            {
                syslog(LOG_CRIT,
                       "Couldn't read signal, wrong size read(fsdi '%ld' != read() '%ld')",
                       sizeof(fdsi),
                       read_size);
                __kill_children();
                exit(EXIT_FAILURE);
            }

            if (fdsi.ssi_signo == SIGINT ||
                fdsi.ssi_signo == SIGTERM)
            {
                // TODO TELL CHILDREN TO DIE
                __kill_children();
                __client_request_close = true;
                break;
            }

            syslog(LOG_CRIT,
                   "Received unexpected signal ? ");
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


static void __handle_client(void)
{
    static unsigned long long client_id = 0;
    char buffer[COMMUNICATION_BUFFER_SIZE];

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

    fd_set readfds;
    struct timeval tv;

    tv.tv_sec = 10;
    tv.tv_usec = 0;
    FD_ZERO(&readfds);
    FD_SET(client_fd, &readfds);

    int retval;
    while ((retval = select(client_fd + 1, &readfds, NULL, NULL, &tv)))
    {
        ssize_t len = read(client_fd, buffer, COMMUNICATION_BUFFER_SIZE - 1);
        if (len > 0)
        {
            syslog(LOG_NOTICE, "Client %llu has connected to dameon.", client_id);

            // FD_ISSET(0, &readfds) will be true.
            buffer[len] = '\0';
            syslog(LOG_NOTICE, "Received command %s from client %llu\n", buffer, client_id);
            command_response_t response;
            __handle_command(buffer, client_id, &response);
            write(client_fd, response.response, strlen(response.response));
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
