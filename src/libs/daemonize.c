#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <stdio.h>
#include "include/daemonize.h"
#include "include/reportman.h"



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