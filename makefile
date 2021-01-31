CC=gcc
CFLAGS=-Wall -O3 -flto

all: mcrcond

mcrcond: mcrcond.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f *.o mcrcond
