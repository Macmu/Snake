#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 40;
    timer_t ts[256];
    int made = 0;
    for (int i = 0; i < n && i < 256; i++) {
        struct sigevent ev;
        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &ts[i])) break;
        made++;
    }
    printf("MADE %d pid %d\n", made, getpid());
    usleep(50000);
    for (int i = 0; i < made; i++) timer_delete(ts[i]);
    return 0;
}
