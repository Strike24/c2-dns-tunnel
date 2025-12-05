CC = gcc
CFLAGS = -Wall -g

all: listener

listener: listener.c listener.h
	$(CC) $(CFLAGS) listener.c -o listener

clean:
	rm -f listener