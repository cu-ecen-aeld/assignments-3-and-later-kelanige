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

struct Parameters
{
    int run;
    FILE *output_fd;
    int serv_fd;
    int peer_fd;
    pid_t pid;
};

struct Parameters parameters;

struct Node
{
    SLIST_ENTRY(Node)
    next;
    pthread_t thread;
    FILE *log;
    pthread_mutex_t *mutex;
    int peer;
    int complete;
    int exit;
};

SLIST_HEAD(NodeHead, Node);
struct NodeHead thread_list;

// Inserts a new entry into a list and returns a pointer to the inserted Node.
struct Node *insert_node(struct NodeHead *head)
{
    struct Node *new_node = malloc(sizeof(struct Node));
    memset(new_node, 0, sizeof(struct Node));
    if (SLIST_EMPTY(head))
    {
        SLIST_INSERT_HEAD(head, new_node, next);
    }
    else
    {
        struct Node *current = SLIST_FIRST(head);
        while (SLIST_NEXT(current, next) != NULL)
        {
            current = SLIST_NEXT(current, next);
        }
        SLIST_INSERT_AFTER(current, new_node, next);
    }
    return new_node;
}

int init()
{
    // Zero memory.
    memset(&parameters, 0, sizeof(struct Parameters));

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
    int bytes = 0;
    while (parameters->exit == 0 && (bytes = recv(parameters->peer, chunk, MAX_CHUNK - 1, 0)) > 0)
    {
        chunk[bytes] = '\0';

        // Acquire mutex.
        pthread_mutex_lock(parameters->mutex);

        // Write line to output file.
        if (parameters->log != NULL)
        {
            fputs(chunk, parameters->log);
        }

        // Release mutex.
        pthread_mutex_unlock(parameters->mutex);

        // Break if newline was found.
        if (strpbrk(chunk, "\n") != NULL)
        {
            break;
        }
    }

    // Zero buffer for reuse.
    memset(chunk, 0, sizeof(char) * MAX_CHUNK);

    // Save file position.
    const long int output_position = ftell(parameters->log);
    if (output_position == -1)
    {
        perror("Failed to get file position");
        exit(-1);
    }

    // Acquire mutex.
    pthread_mutex_lock(parameters->mutex);

    // Seek to beginning of file.
    if (fseek(parameters->log, 0, SEEK_SET) != 0)
    {
        perror("Failed to seek to beginning of log file");
        exit(-1);
    }

    // Echo back data.
    while (parameters->exit == 0 && fgets(chunk, MAX_CHUNK, parameters->log) != NULL)
    {
        char *end = strrchr(chunk, '\0');
        if (end == NULL)
        {
            break;
        }
        if (send(parameters->peer, chunk, (size_t)(end - chunk), 0) == -1)
        {
            perror("Call to send failed");
            break;
        }
        memset(chunk, 0, sizeof(char) * MAX_CHUNK);
    }

    // Release mutex.
    pthread_mutex_unlock(parameters->mutex);

    // Set completed.
    parameters->complete = 1;

    // Exit thread.
    pthread_exit(arg);
}

void *log_timestamp(void* arg) {
    struct Node* parameters = (struct Node *)arg;
    const int MAX_SIZE = 1024;
    const struct timespec required = {10, 0};
    char wall_time[MAX_SIZE];
    strcpy(wall_time, "timestamp:");
    while (parameters->exit == 0) {
        // Sleep for 10 seconds.
        if (nanosleep(&required, NULL) != 0) {
            perror("Call to nanosleep failed");
            exit(-1);
        }
        // Get current time.
        time_t t = time(NULL);
        struct tm* current_time = localtime(&t);
        // Log time.
        strftime(wall_time + 10, MAX_SIZE, "%F %T", current_time);
        strcat(wall_time, "\n");
        // Acquire mutex.
        pthread_mutex_lock(parameters->mutex);
        // Write to log file.
        fputs(wall_time, parameters->log);
        // Release mutex.
        pthread_mutex_unlock(parameters->mutex);
    }
    parameters->complete = 1;
    pthread_exit(arg);
}

void join_completed_threads(int req_exit)
{
    struct Node *current, *tmp;
    SLIST_FOREACH_SAFE(current, &thread_list, next, tmp)
    {
        current->exit = req_exit;
        if (current->complete == 1)
        {
            pthread_join(current->thread, NULL);
            // Close peer connection.
            if (close(current->peer) == -1)
            {
                perror("Call to close peer socket failed");
                exit(-1);
            }
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
    if (parameters.serv_fd != 0)
    {
        if (shutdown(parameters.serv_fd, SHUT_RDWR) == -1)
        {
            perror("Call to shutdown failed");
        }
    }

    // Close server socket.
    if (parameters.serv_fd != 0)
    {
        if (close(parameters.serv_fd) == -1)
        {
            perror("Call to close failed");
        }
        parameters.serv_fd = 0;
    }

    // Close output file.
    if (parameters.output_fd != NULL)
    {
        if (fclose(parameters.output_fd) == EOF)
        {
            perror("Failed to close output file");
        }
        parameters.output_fd = NULL;
    }

    // Delete /var/tmp/aesdsocketdata.
    if (access("/var/tmp/aesdsocketdata", F_OK) == 0)
    {
        if (remove("/var/tmp/aesdsocketdata") == -1)
        {
            perror("Call to remove failed");
        }
    }

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
    const int MAX_CONNECTIONS = 5;

    // Register signal handlers.
    struct sigaction handler;
    handler.sa_handler = sigint_handler;
    sigemptyset(&handler.sa_mask);
    handler.sa_flags = 0;
    if (sigaction(SIGINT, &handler, NULL) == -1)
    {
        perror("Call to sigaction failed");
        exit(-1);
    }
    if (sigaction(SIGTERM, &handler, NULL) == -1)
    {
        perror("Call to sigaction failed");
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

    // Open output file.
    parameters.output_fd = fopen("/var/tmp/aesdsocketdata", "a+");
    if (parameters.output_fd == NULL)
    {
        perror("Failed to open output file");
        exit(-1);
    }
    pthread_mutex_t log_mutex;

    // Spawn timestamp thread.
    struct Node *timer_node = insert_node(&thread_list);
    timer_node->log = parameters.output_fd;
    timer_node->mutex = &log_mutex;
    timer_node->exit = 0;
    pthread_create(&timer_node->thread, NULL, log_timestamp, (void *)timer_node);

    while (parameters.run)
    {
        // Accept an incoming connection.
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        const int peer = accept(parameters.serv_fd, (struct sockaddr *)&peer_addr, &peer_len);
        if (peer == -1)
        {
            perror("Call to accept failed");
            exit(-1);
        }
        char peer_ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &(peer_addr.sin_addr), peer_ip, INET_ADDRSTRLEN) == NULL)
        {
            perror("Call to inet_ntop failed");
            exit(-1);
        }
        syslog(LOG_INFO, "Acceped connection from %s", peer_ip);
        struct Node *node = insert_node(&thread_list);
        node->log = parameters.output_fd;
        node->mutex = &log_mutex;
        node->peer = peer;
        node->complete = 0;
        node->exit = 0;
        pthread_create(&node->thread, NULL, handle_connection, (void *)node);
        join_completed_threads(0);
    }

    cleanup();
    exit(EXIT_SUCCESS);
}