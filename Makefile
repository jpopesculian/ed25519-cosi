CFLAGS=-I/usr/local/include
LDFLAGS=-L/usr/local/lib -lsodium
CC = gcc

SRC = ed25519_cosi.c
OUT = ed25519_cosi.o

.PHONY:all clean

all: build

build:
	$(CC) $(CFLAGS) -o $(OUT) -c $(SRC) $(LDFLAGS)

clean:
	rm -f $(OUT)
