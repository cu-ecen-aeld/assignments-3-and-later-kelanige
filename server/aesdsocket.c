#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

struct Parameters
{
    int run;
    FILE *output_fd;
    int serv_fd;
    int peer_fd;
    pid_t pid;
};

struct Parameters parameters;

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

int cleanup()
{
    // Set stop.
    parameters.run = 0;

    // Shutdown peer socket.
    if (parameters.peer_fd != 0)
    {
        if (shutdown(parameters.peer_fd, SHUT_RDWR) == -1)
        {
            perror("Call to shutdown failed");
        }
    }
    // Shutdown server socket.
    if (parameters.serv_fd != 0)
    {
        if (shutdown(parameters.serv_fd, SHUT_RDWR) == -1)
        {
            perror("Call to shutdown failed");
        }
    }
    // Close peer socket.
    if (parameters.peer_fd != 0)
    {
        if (close(parameters.peer_fd) == -1)
        {
            perror("Call to close failed");
        }
        parameters.peer_fd = 0;
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
    const int MAX_CHUNK = 1024;
    const int MAX_CONNECTIONS = 1;

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

    while (parameters.run)
    {
        // Accept an incoming connection.
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        parameters.peer_fd = accept(parameters.serv_fd, (struct sockaddr *)&peer_addr, &peer_len);
        if (parameters.peer_fd == -1)
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
        // Open output file.
        parameters.output_fd = fopen("/var/tmp/aesdsocketdata", "a+");
        if (parameters.output_fd == NULL)
        {
            perror("Failed to open output file");
            exit(-1);
        }
        // Read data.
        char chunk[MAX_CHUNK];
        int bytes = 0;
        int total_bytes = 0;
        while ((bytes = recv(parameters.peer_fd, chunk, MAX_CHUNK - 1, 0)) > 0)
        {
            chunk[bytes] = '\0';

            // Write line to output file.
            if (parameters.output_fd != NULL)
            {
                fputs(chunk, parameters.output_fd);
                total_bytes += bytes;
            }

            // Break if newline was found.
            if (strpbrk(chunk, "\n") != NULL)
            {
                break;
            }
        }
        if (fclose(parameters.output_fd) == EOF)
        {
            perror("Call to close file failed");
            exit(-1);
        }
        parameters.output_fd = 0;

        // Zero buffer for reuse.
        memset(chunk, 0, sizeof(char) * MAX_CHUNK);

        // Open file in read mode.
        parameters.output_fd = fopen("/var/tmp/aesdsocketdata", "r");
        if (parameters.output_fd == NULL)
        {
            perror("Failed to open data file in read mode");
            exit(-1);
        }

        // Echo back data.
        while (fgets(chunk, MAX_CHUNK, parameters.output_fd) != NULL)
        {
            char *end = strrchr(chunk, '\0');
            if (end == NULL)
            {
                break;
            }
            if (send(parameters.peer_fd, chunk, (size_t)(end - chunk), 0) == -1)
            {
                perror("Call to send failed");
                break;
            }
            memset(chunk, 0, sizeof(char) * MAX_CHUNK);
        }

        // Close output file.
        if (fclose(parameters.output_fd) == EOF)
        {
            perror("Call to close file failed");
            exit(-1);
        }
        parameters.output_fd = 0;

        // Close peer connection.
        if (close(parameters.peer_fd) == -1)
        {
            perror("Call to close peer socket failed");
            exit(-1);
        }
        parameters.peer_fd = 0;
    }
    exit(EXIT_SUCCESS);
}