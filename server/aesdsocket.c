#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "queue.h"

#ifndef USE_AESD_CHAR_DEVICE
#define USE_AESD_CHAR_DEVICE 1
#endif

#if USE_AESD_CHAR_DEVICE
    const char* filename = "/dev/aesdchar";
#else
    const char* filename = "/var/tmp/aesdsocketdata";
#endif

struct Parameters
{
    int run;
    int serv_fd;
};

struct Parameters parameters;

struct Node
{
    SLIST_ENTRY(Node)
    next;
    pthread_t thread;
    pthread_mutex_t *mutex;
    int peer;
    int complete;
    int *run;
};

SLIST_HEAD(NodeHead, Node);
struct NodeHead thread_list;

// Inserts a new entry into a list and returns a pointer to the inserted Node.
struct Node *insert_node(struct NodeHead *head)
{
    struct Node *new_node = malloc(sizeof(struct Node));
    memset(new_node, 0, sizeof(struct Node));
    SLIST_INSERT_HEAD(head, new_node, next);
    return new_node;
}

int init()
{
    // Zero memory.
    memset(&parameters, 0, sizeof(struct Parameters));
    memset(&thread_list, 0, sizeof(struct NodeHead));

    // Open syslog.
    openlog(NULL, LOG_CONS | LOG_PERROR, LOG_USER);

    // Set run.
    parameters.run = 1;

    return 0;
}

void *handle_connection(void *arg)
{
    struct Node *parameters = (struct Node *)arg;
    const int MAX_CHUNK = 1024;
    // Read data.
    char chunk[MAX_CHUNK];
    memset(chunk, 0, MAX_CHUNK);
    int bytes = 0;
    FILE* log = fopen(filename, "a+");
    while (*parameters->run == 1 && (bytes = recv(parameters->peer, chunk, MAX_CHUNK - 1, 0)) > 0)
    {
        // Acquire mutex.
        pthread_mutex_lock(parameters->mutex);

        // Write line to output file.
        if (log != NULL)
        {
            fprintf(log, "%s", chunk);
        }

        // Release mutex.
        pthread_mutex_unlock(parameters->mutex);

        // Break if newline was found.
        if (strpbrk(chunk, "\n") != NULL)
        {
            break;
        }
        memset(chunk, 0, MAX_CHUNK);
    }

    if (*parameters->run == 1)
    {
        // Acquire mutex.
        pthread_mutex_lock(parameters->mutex);
        // Seek to beginning of file.
        if (fseek(log, 0, SEEK_SET) != 0)
        {
            perror("Failed to seek to beginning of file");
        }
        // Echo back data.
        size_t bytes_read = 0;
        while (*parameters->run == 1 && (bytes_read = fread(chunk, sizeof(char), MAX_CHUNK, log)) != 0)
        {
            if (send(parameters->peer, chunk, bytes_read, 0) != bytes_read)
            {
                perror("Call to send failed");
            }
            memset(chunk, 0, MAX_CHUNK);
        }
        // Release mutex.
        pthread_mutex_unlock(parameters->mutex);
    }
    fclose(log);
    // Set completed.
    parameters->complete = 1;
    // Exit thread.
    return NULL;
}

void *log_timestamp(void *arg)
{
    struct Node *parameters = (struct Node *)arg;
    const int MAX_SIZE = 1024;
    time_t last_log_time = time(NULL);
    FILE* log = fopen(filename, "a+");
    while (*parameters->run == 1)
    {
        // Get current time.
        const time_t now = time(NULL);
        // Check to see if 10 seconds have elapsed since last log.
        if (now - last_log_time > 9)
        {
            char wall_time[MAX_SIZE];
            char tmp[MAX_SIZE];
            memset(wall_time, 0, MAX_SIZE);
            memset(tmp, 0, MAX_SIZE);
            strcat(wall_time, "timestamp:");
            // Log time.
            struct tm *current_time = localtime(&now);
            strftime(tmp, MAX_SIZE, "%F %T", current_time);
            strcat(wall_time, tmp);
            strcat(wall_time, "\0");
            // Acquire mutex.
            pthread_mutex_lock(parameters->mutex);
            // Write to log file.
            fprintf(log, "%s\n", wall_time);
            // Release mutex.
            pthread_mutex_unlock(parameters->mutex);
            // Update last log time.
            last_log_time = now;
        }
    }
    fclose(log);
    // Set completed.
    parameters->complete = 1;
    // Exit thread.
    return NULL;
}

void join_completed_threads(int force_exit)
{
    struct Node *current, *tmp;
    SLIST_FOREACH_SAFE(current, &thread_list, next, tmp)
    {
        if (current->complete == 1 || force_exit == 1)
        {
            pthread_join(current->thread, NULL);
            SLIST_REMOVE(&thread_list, current, Node, next);
            free(current);
        }
    }
}

int cleanup()
{
    // Set stop.
    parameters.run = 0;
    // Shutdown peer sockets.
    do
    {
        join_completed_threads(1);
    } while (!SLIST_EMPTY(&thread_list));

    // Shutdown server socket.
    if (shutdown(parameters.serv_fd, SHUT_RDWR) == -1)
    {
        perror("Call to shutdown failed");
    }

    // Close server socket.
    if (close(parameters.serv_fd) == -1)
    {
        perror("Call to close failed");
    }
    parameters.serv_fd = 0;

#if USE_AESD_CHAR_DEVICE
#else
    if (remove(filename) != 0) {
        perror("Failed to remove output file");
    }
#endif

    // Close syslog.
    closelog();
    return 0;
}

void sigint_handler(int signum)
{
    syslog(LOG_INFO, "Caught signal, exiting");
    cleanup();
}

int main(int argc, char *argv[])
{
    const int MAX_CONNECTIONS = 10;

    // Register signal handlers.
    struct sigaction handler;
    handler.sa_handler = sigint_handler;
    sigemptyset(&handler.sa_mask);
    handler.sa_flags = 0;
    if (sigaction(SIGINT, &handler, NULL) == -1)
    {
        perror("Call to sigaction failed for SIGINT");
        exit(-1);
    }
    if (sigaction(SIGTERM, &handler, NULL) == -1)
    {
        perror("Call to sigaction failed for SIGTERM");
        exit(-1);
    }

    // Initialize.
    if (init() == -1)
    {
        exit(-1);
    }

    // Get the socket file descriptor.
    parameters.serv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (parameters.serv_fd == -1)
    {
        perror("Call to socket failed");
        exit(-1);
    }

    // Set socket options.
    if (setsockopt(parameters.serv_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
    {
        perror("Call to setsockopt failed");
        exit(-1);
    }

    // Bind the socket to address and port.
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(9000);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(parameters.serv_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("Call to bind failed");
        exit(-1);
    }

    // Check for daemon mode.
    if (argc > 1 && strcmp(argv[1], "-d") == 0)
    {
        if (daemon(0, 0) == -1)
        {
            perror("Call to daemon failed");
            exit(-1);
        }
    }

    // Listen for connections.
    if (listen(parameters.serv_fd, MAX_CONNECTIONS) == -1)
    {
        perror("Call to listen failed");
        exit(-1);
    }

    // Initialize mutex.
    pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

#if USE_AESD_CHAR_DEVICE
#else
    // Spawn timestamp thread.
    struct Node *timer_node = insert_node(&thread_list);
    timer_node->mutex = &log_mutex;
    timer_node->complete = 0;
    timer_node->run = &parameters.run;
    pthread_create(&timer_node->thread, NULL, log_timestamp, (void *)timer_node);
#endif

    while (parameters.run)
    {
        // Accept an incoming connection.
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        const int peer = accept(parameters.serv_fd, (struct sockaddr *)&peer_addr, &peer_len);
        if (peer == -1)
        {
            perror("Call to accept failed");
        }
        char peer_ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &(peer_addr.sin_addr), peer_ip, INET_ADDRSTRLEN) == NULL)
        {
            perror("Call to inet_ntop failed");
        }
        if (parameters.run)
        {
            syslog(LOG_INFO, "Acceped connection from %s", peer_ip);
            struct Node *node = insert_node(&thread_list);
            node->mutex = &log_mutex;
            node->peer = peer;
            node->complete = 0;
            node->run = &parameters.run;
            pthread_create(&node->thread, NULL, handle_connection, (void *)node);
        }
        join_completed_threads(0);
    }

    exit(EXIT_SUCCESS);
}
