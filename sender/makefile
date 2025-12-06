CC = gcc
CFLAGS = -Wall -g

all: sender

sender: sender.c sender.h
	$(CC) $(CFLAGS) sender.c -o sender -lresolv

clean:
	rm -f sender