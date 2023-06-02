INCLUDE_DIRS =
LIB_DIRS =
CC = gcc

CDEFS =
CFLAGS = -O0 -Wall -Werror -g $(INCLUDE_DIRS) $(CDEFS)
LIBS =

HFILES =
CFILES = aesdsocket.c

SRCS = ${HFILES} ${CFILES}
OBJS = ${CFILES:.c=.o}

all: aesdsocket
default: aesdsocket

clean:
	-rm -f *.o *.d
	-rm -f aesdsocket

aesdsocket: aesdsocket.o
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $@.o

.c.o:
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c $<
