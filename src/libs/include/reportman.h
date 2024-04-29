#ifndef REPORTMAND_BIND_PORT
#define REPORTMAND_BIND_PORT 7770

#define IS_SINGLETON 0
#define BIND_FAILED -1
#define M_LOG_PATH "/var/log/reportman/monitor.log"

#define D_SUCCESS 0
#define D_FAILURE -1
#define D_FAILURE_TIMEOUT -2

#define COMMUNICATION_BUFFER_SIZE 1024

#define COMMAND_NOT_FOUND 127
#define COMMAND_SUCCESSFUL 0
#define COMMAND_ERROR 1

#define LSOF_FD_NOT_FOUND 2

char* join_paths(const char* path1, const char* path2);
void split_path(const char *path, char **directory, char **filename);


#endif
