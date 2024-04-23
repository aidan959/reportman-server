int d_acquire_singleton(int *sockfd, short unsigned singleton_port);
enum
{
    RMD_FD_POLL_SIGNAL = 0,
    RMD_FD_POLL_CLIENT = 1,
    RMD_FD_POLL_MAX = 2
};
