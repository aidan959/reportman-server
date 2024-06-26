#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/signalfd.h>


#include <signal.h>

#include <unistd.h>

#include <stdio.h>
#include "include/daemonize.h"
#include "include/reportman.h"
#include "include/reportman_types.h"

static int __get_other_pid(unsigned short singleton_port);
static char *__save_pipe_buffer(FILE *fp); 
static unsigned long __parse_lsof_output(char *lsof_output, running_pid_t **pids);
static running_pid_t *__parse_lsof_line(char *line); 
static void __free_running_pids(running_pid_t *pid, unsigned long num_pids);


int d_acquire_singleton(int *sockfd, short unsigned singleton_port)
{
    struct sockaddr_in addr;

    // Create a socket
    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*sockfd < 0)
    {
        fprintf(stderr, "Cannot create singleton socket: %s", strerror(errno));
        return D_FAILURE;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(singleton_port);

    if (bind(*sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        fprintf(stderr, "Bind failed - another instance of reportmand may be running on port(%hu): %s\n", singleton_port, strerror(errno));
        return __get_other_pid(singleton_port);
    }

    if (listen(*sockfd, 5) < 0)
    {
        fprintf(stderr, "Listening on singleton socket failed: %s\n", strerror(errno));
        close(*sockfd);
        exit(EXIT_FAILURE);
    }
    return IS_SINGLETON;
}
void kill_pid(int singleton_result)
{
    if (kill(singleton_result, SIGTERM) < 0)
    {
        perror("Error killing other process, use systemctl instead.");
        exit(errno);
    }
}

/// @brief gets the PID if the singleton port is not available.
/// @param singleton_port
/// @return result of the command
static int __get_other_pid(unsigned short singleton_port)
{
    FILE *fp;

    char *lsof_output = NULL;
    unsigned long num_of_pids = 0;

    // Create the command string
    char command[50];
    sprintf(command, "lsof -i :%hu", singleton_port);

    // Execute the command and open a pipe to read its output
    fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("Failed to run lsof");
        return 0;
    }
    // make copy of buffer before pipe close
    lsof_output = __save_pipe_buffer(fp);

    switch (pclose(fp))
    {
    case COMMAND_SUCCESSFUL:
        break;
    case LSOF_FD_NOT_FOUND:
        free(lsof_output);
        // TODO IMPLEMENT RETRY PATTERN IF THIS CASE HAPPENS - WE MAY HAVE GRABBED THE PORT TOO EARLY
        printf("No processes is using the singleton port %d\n", singleton_port);
        return -1;
    case COMMAND_NOT_FOUND:
        free(lsof_output);
        printf("lsof was not found by the shell. Please install LSOF to get the process id of conflicting host.");
        return -2;
    case COMMAND_ERROR:
        free(lsof_output);
        return -1;
    default:
        // command wasnt successful - free buffer and return
        free(lsof_output);
        return -1;
    }
    running_pid_t *running_pids = NULL;
    num_of_pids = __parse_lsof_output(lsof_output, &running_pids);
    int pid = running_pids[0].pid;
    for (unsigned long i = 0; i < num_of_pids; i++)
    {
        printf("Process \"%s\" (PID: %d) is using the singleton port %d\n", running_pids[i].command, running_pids[i].pid, singleton_port);
    }
    free(lsof_output);
    __free_running_pids(running_pids, num_of_pids);
    return pid;
}




/// @brief Parses output line of LSOF and
/// @param lsof_output
/// @param pid
/// @return
static unsigned long __parse_lsof_output(char *lsof_output, running_pid_t **pids)
{
    char *line;
    running_pid_t *running_pids;
    unsigned long capcacity = 0;
    unsigned long count = 0;
    char *save_pointer = NULL;
    line = strtok_r(lsof_output, "\n", &save_pointer);
    while (line != NULL)
    {
        if (count >= capcacity)
        {
            // reduces number of extra assignments
            capcacity = capcacity == 0 ? 2 : capcacity * 2;
            running_pid_t *new_running_pids = realloc(running_pids, sizeof(running_pid_t) * capcacity);
            if (!new_running_pids)
            {
                free(running_pids);
                perror("Failed to malloc to display PIDS.");
                exit(1);
            }
            running_pids = new_running_pids;
        }

        running_pid_t *pid = __parse_lsof_line(line);
        if (pid == NULL)
        {
            line = strtok_r(NULL, "\n", &save_pointer);
            continue;
        }
        running_pids[count++] = *pid;
        line = strtok_r(NULL, "\n", &save_pointer);
    }
    *pids = running_pids;
    return count;
}

static char *__save_pipe_buffer(FILE *fp)
{
    char buffer[1024];
    size_t data_allocated = 0;
    size_t data_used = 0;
    char *lsof_output = NULL;
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        size_t bufferLen = strlen(buffer);

        // Ensure there's enough space in the lsof_output buffer
        if (data_used + bufferLen + 1 > data_allocated)
        {
            size_t new_allocated = data_allocated == 0 ? bufferLen * 2 : data_allocated * 2;
            char *newData = realloc(lsof_output, new_allocated);
            if (!newData)
            {
                perror("Failed to allocate memory");
                free(lsof_output);
                pclose(fp);
                exit(1);
            }
            lsof_output = newData;
            data_allocated = new_allocated;
        }

        // Append the new lsof_output
        memcpy(lsof_output + data_used, buffer, bufferLen);
        data_used += bufferLen;
        lsof_output[data_used] = '\0'; // Ensure the string is null-terminated
    }
    return lsof_output;
}



static running_pid_t *__parse_lsof_line(char *line)
{
    char type[512], node[512], protocol[512], address[512], state[512];
    int pid, fd;
    char device[512], size_off[512];
    // heap allocate command so it can be returned
    char *command = malloc(sizeof(char) * 512);
    // Example format: "reportmand 1234 user 7u IPv4 7770 0t0 TCP *:http (LISTEN)"
    int result = sscanf(line, "%s %d %*s %d%s %s %s %s %s %s %s",
                        command, &pid, &fd, type, device, size_off, node, protocol, address, state);

    // Check if the line was parsed successfully
    if (result >= 9)
    {
        running_pid_t *running_pid = malloc(sizeof(running_pid));
        running_pid->pid = pid;
        running_pid->command = command;
        return running_pid;
    }
    free(command);
    return NULL;
}
void __free_running_pids(running_pid_t *pid, unsigned long num_pids)
{
    for (unsigned long i = 0; num_pids < i; i++)
    {
        free(pid[i].command);
    }
    free(pid);
}


int r_initialize_signals(void)
{
    int signal_fd;
    sigset_t sigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTERM);

    if (sigprocmask(SIG_BLOCK, &sigmask, NULL) < 0)
    {
        syslog(LOG_ERR,
               "Couldn't block signals: '%s'\n",
               strerror(errno));
        return -1;
    }

    // get new file descriptor for signals
    if ((signal_fd = signalfd(-1, &sigmask, 0)) < 0)
    {
        syslog(LOG_ERR,
               "Couldn't setup signal FD: '%s'\n",
               strerror(errno));
        return -1;
    }
    // signal(SIGINT, __clean_close);
    // signal(SIGTERM, __clean_close);
    return signal_fd;
}