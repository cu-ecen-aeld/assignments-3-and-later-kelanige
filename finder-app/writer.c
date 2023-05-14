#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

const int LOG_OPTIONS = LOG_CONS;

int main(int argc, char* argv[]) {
	openlog(NULL, LOG_OPTIONS, LOG_USER);
	if (argc != 3) {
		syslog(LOG_ERR, "Incorrect number of arguments, expected 3, got %d. Usage: ./writer /path/to/file text", argc);
		closelog();
		exit(1);
	}

	FILE* file = fopen(argv[1], "w");

	if (file == NULL) {
		const int err = errno;
		perror("Error occured while opening file");
		syslog(LOG_ERR, "Encountered error while opening %s. %s.", argv[1], strerror(err));
		exit(1);
	}

	syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
	fprintf(file, "%s", argv[2]);
	fclose(file);
	closelog();
	exit(0);
}

