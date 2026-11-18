#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    /* 一对一 fork，父进程保持存活，便于 trace 只覆盖这一次 fork */
    pid_t me = getpid();
    printf("PARENT %d\n", me);
    fflush(stdout);
    usleep(200000);
    pid_t c = fork();
    if (c == 0) {
        usleep(400000);
        _exit(0);
    }
    printf("CHILD %d\n", c);
    fflush(stdout);
    usleep(400000);
    return 0;
}