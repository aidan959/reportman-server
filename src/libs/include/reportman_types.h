#include <stdbool.h>

typedef struct
{
    bool make_daemon;
    bool force;
    bool close;
    bool log_to_sys;
    bool log_to_file;
    const char *backup_directory;
    const char *reports_directory;
    const char *dashboard_directory;
    unsigned short daemon_port;
    const char* backup_time_str;
    const char* transfer_time_str;

} daemon_arguments_t;

typedef struct
{
    int pid;
    char * command;
} running_pid_t;
