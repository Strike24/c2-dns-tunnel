CC = gcc
CFLAGS = -Wall -g -lresolv

all: sender

sender: sender.c listener.h
	$(CC) $(CFLAGS) sender.c -o sender

clean:
	rm -f sender