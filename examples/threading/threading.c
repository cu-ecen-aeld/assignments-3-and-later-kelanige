#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg, ...)
// #define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg, ...) printf("threading ERROR: " msg "\n", ##__VA_ARGS__)

struct timespec ms_to_timespec(int time_ms)
{
    struct timespec result;
    result.tv_sec = time_ms / 1000;
    result.tv_nsec = (time_ms % 1000) * 1000000;
    return result;
}

void *threadfunc(void *thread_param)
{
    struct thread_data *params = (struct thread_data *)thread_param;
    const struct timespec wait_to_obtain = ms_to_timespec(params->wait_to_obtain_ms);
    const struct timespec wait_to_release = ms_to_timespec(params->wait_to_release_ms);
    struct timespec remaining_sleep;
    // In the following sequence, fail and return early if any of the function calls fail.
    // Wait specified number of milliseconds before acquiring the lock.
    if (nanosleep(&wait_to_obtain, &remaining_sleep) != 0)
    {
        return thread_param;
    }
    // Acquire the lock.
    if (pthread_mutex_lock(params->mutex) != 0)
    {
        return thread_param;
    }
    // Simulate work.
    if (nanosleep(&wait_to_release, &remaining_sleep) != 0)
    {
        return thread_param;
    }
    // Release the lock.
    if (pthread_mutex_unlock(params->mutex) != 0)
    {
        return thread_param;
    }
    params->thread_complete_success = true;
    return thread_param;
}

bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex, int wait_to_obtain_ms, int wait_to_release_ms)
{
    struct thread_data *thread_param = malloc(sizeof(struct thread_data));
    thread_param->mutex = mutex;
    thread_param->wait_to_obtain_ms = wait_to_obtain_ms;
    thread_param->wait_to_release_ms = wait_to_release_ms;
    thread_param->thread_complete_success = false;

    return pthread_create(thread, NULL, threadfunc, thread_param) == 0;
}
