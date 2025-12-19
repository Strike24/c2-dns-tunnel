CC = gcc
CFLAGS = -Wall -g

all: listener

listener: listener.c listener.h payloads.c payloads.h ../headers/base64.c ../headers/base64.h
	$(CC) $(CFLAGS) listener.c payloads.c ../headers/base64.c -o listener

clean:
	rm -f listener