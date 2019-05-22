CFLAGS=-Wall
LDFLAGS=

TEST_CFLAGS=
TEST_LDFLAGS=-lcheck -pthread -lcheck_pic -pthread -lrt -lm -lsubunit -lsodium

CC = clang

SRC = ed25519_cosi.c
OUT = ed25519_cosi.o

SRC_TEST = ed25519_cosi_test.c
OUT_TEST = ed25519_cosi_test

TEST_SRC = ed25519_cosi_test.c

.PHONY:all clean watch

all: build

build:
	$(CC) $(CFLAGS) -o $(OUT) -c $(SRC) $(LDFLAGS)

clean:
	rm -f $(OUT)
	rm -f $(OUT_TEST)

build-check: build
	$(CC) $(CFLAGS) -o $(OUT_TEST) $(SRC_TEST) $(OUT) $(LDFLAGS) $(TEST_CFLAGS) $(TEST_LDFLAGS)

check: build-check
	./$(OUT_TEST)

watch:
	./watch
