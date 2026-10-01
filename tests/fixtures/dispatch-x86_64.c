#include <dispatch/dispatch.h>
#include <stdatomic.h>
#include <stdio.h>

// libdispatch on the kernel workqueue: concurrent work on a global queue
// joined by a group, a serial queue signaling a semaphore, and a timer-driven
// dispatch_after. Each stage prints as it completes so a hang shows where.

enum { blockCount = 16 };

int main(void) {
    dispatch_queue_t global = dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0);
    dispatch_group_t group = dispatch_group_create();
    static _Atomic long total;
    for (long index = 1; index <= blockCount; ++index) {
        dispatch_group_async(group, global, ^{
            atomic_fetch_add(&total, index);
        });
    }
    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
    printf("DISPATCH group total=%ld\n", atomic_load(&total));

    dispatch_queue_t serial = dispatch_queue_create("rosa.serial", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    static long order;
    for (long index = 0; index < 4; ++index) {
        dispatch_async(serial, ^{
            order = order * 10 + index + 1;
        });
    }
    dispatch_async(serial, ^{
        dispatch_semaphore_signal(semaphore);
    });
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    printf("DISPATCH serial order=%ld\n", order);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_MSEC), global, ^{
        dispatch_semaphore_signal(semaphore);
    });
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    printf("DISPATCH after fired\n");
    return atomic_load(&total) == blockCount * (blockCount + 1) / 2 && order == 1234 ? 0 : 1;
}
