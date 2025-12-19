CC = gcc
CFLAGS = -Wall -g

all: sender

sender: sender.c sender.h ../headers/base64.c ../headers/base64.h
	$(CC) $(CFLAGS) sender.c ../headers/base64.c -o sender -lresolv

clean:
	rm -f sender