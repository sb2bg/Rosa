#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

// Four threads contend on one mutex, report through a condition variable, and
// are joined for their return values. Exercises guest thread creation,
// scheduling, blocking waits, and thread exit.

enum { threadCount = 4, iterations = 20000 };

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t finished = PTHREAD_COND_INITIALIZER;
static long counter;
static int done;

static void *worker(void *argument) {
    for (int index = 0; index < iterations; ++index) {
        pthread_mutex_lock(&lock);
        ++counter;
        pthread_mutex_unlock(&lock);
    }
    pthread_mutex_lock(&lock);
    ++done;
    pthread_cond_signal(&finished);
    pthread_mutex_unlock(&lock);
    return (void *)((intptr_t)argument * 10);
}

int main(void) {
    pthread_t threads[threadCount];
    for (intptr_t index = 0; index < threadCount; ++index) {
        if (pthread_create(&threads[index], NULL, worker, (void *)(index + 1)) != 0) {
            printf("pthread_create failed\n");
            return 1;
        }
    }
    pthread_mutex_lock(&lock);
    while (done < threadCount) {
        pthread_cond_wait(&finished, &lock);
    }
    pthread_mutex_unlock(&lock);

    intptr_t sum = 0;
    for (int index = 0; index < threadCount; ++index) {
        void *result = NULL;
        pthread_join(threads[index], &result);
        sum += (intptr_t)result;
    }
    printf("THREADS counter=%ld joined=%ld\n", counter, (long)sum);
    return counter == (long)threadCount * iterations && sum == 100 ? 0 : 1;
}
