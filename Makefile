CFLAGS=-I/usr/local/include -Wall
LDFLAGS=-L/usr/local/lib -lsodium
TEST_FLAGS=-lcheck -pthread -lcheck_pic -pthread -lrt -lm -lsubunit
CC = gcc

SRC = ed25519_cosi.c
OUT = ed25519_cosi.o

SRC_TEST = ed25519_cosi_test.c
OUT_TEST = ed25519_cosi_test

TEST_SRC = ed25519_cosi_test.c

.PHONY:all clean

all: build

build:
	$(CC) $(CFLAGS) -o $(OUT) -c $(SRC) $(LDFLAGS)

clean:
	rm -f $(OUT)
	rm -f $(OUT_TEST)

build-test: build
	$(CC) $(CFLAGS) -o $(OUT_TEST) $(SRC_TEST) $(LDFLAGS) $(TEST_FLAGS)

check: build-test
	./$(OUT_TEST)
