#include "systemcalls.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{
    const int status = system(cmd);

    if (cmd == NULL && status == 0) {
        // No shell is available.
        return false;
    } else if (status == -1) {
        // Child could not be created, or status could not be retrieved.
        // const int err = errno;
        return false;
    } else if (status == 127) {
        // Shell could not be executed in the child process.
        return false;
    }
   
    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
        printf("%s\n", command[i]);
    }
    command[count] = NULL;
    va_end(args);

    bool status = false;
    const pid_t pid = fork();

    if (pid == 0) {
        // Child process.
        if (execv(command[0], command) == -1) {
            // Error in execv.
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    } else if (pid == -1) {
        // Failed to fork.
        // const int err = errno;
        status = false;
    } else {
        // Parent process.
        int execv_result = 0;
        const int terminated_pid = wait(&execv_result);
        status = (terminated_pid == -1);
        if (WIFEXITED(execv_result)) {
            status = (WEXITSTATUS(execv_result) == EXIT_SUCCESS);
        } else if (WIFSIGNALED(execv_result)) {
        }
    }
    return status;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    va_end(args);

    const int log = open(outputfile, O_WRONLY | O_CREAT);
    if (log == -1) {
        // Failed to open output file.
        // const int err = errno;
        return false;
    }
    bool status = false;
    const pid_t pid = fork();

    if (pid == 0) {
        // Child process.
        if (dup2(log, 1) == -1) {
            // Error when redirecting output.
            // const int err = errno;
            exit(EXIT_FAILURE);
        }
        if (close(log) == -1) {
            // Error when closing log file.
            // const int err = errno;
            ;
        }
        if (execv(command[0], command) == -1) {
            // Error in execv.
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    } else if (pid == -1) {
        // Failed to fork.
        // const int err = errno;
        status = false;
    } else {
        // Parent process.
        if (close(log) == -1) {
            // Error when closing log file.
            // const int err = errno;
            ;
        }
        int execv_result = 0;
        const int terminated_pid = wait(&execv_result);
        status = (terminated_pid == -1);
        if (WIFEXITED(execv_result)) {
            status = (WEXITSTATUS(execv_result) == EXIT_SUCCESS);
        } else if (WIFSIGNALED(execv_result)) {
            status = false;
        }
    }

    return status;
}
