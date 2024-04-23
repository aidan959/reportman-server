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



#include "include/reportman_server.h"
#include "libs/include/reportman.h"
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
// --- all just to do with singleton aquisition
static void __acquire_singleton(void);
static int __force_singleton(int singleton_result, unsigned short port);
static void __kill_pid(int pid); // TODO maybe move some process managing tool?
static int __get_other_pid(unsigned short singleton_port); // OK this needs to be in another tool
static running_pid_t *__parse_lsof_line(char *line); // silly
static unsigned long __parse_lsof_output(char *lsof_output, running_pid_t **pids); // like fr
static char *__save_pipe_buffer(FILE *fp); // ludcirous
// ---
int __force_singleton(int singleton_result, unsigned short port)
{
    syslog(LOG_WARNING, "Forcing reportman_server to start on port %d", port);
    printf("Forcing reportman_server to start on port %d\n", port);

    __kill_pid(singleton_result);
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
            __kill_pid(singleton_result);
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
static void __kill_pid(int singleton_result)
{
    if (kill(singleton_result, SIGTERM) < 0)
    {
        perror("Error killing other process, use systemctl instead.");
        exit(errno);
    }
}
int main (void) {
    // ! TODO: Populate arguments
    
    __acquire_singleton();

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