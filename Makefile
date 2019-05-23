CFLAGS=-Wall -I/usr/local/include -I. -fPIC
LDFLAGS=

TEST_CFLAGS=
TEST_LDFLAGS=-L. -lsodium -lcheck -pthread -lcheck_pic -pthread -lrt -lm -lsubunit -led25519_cosi

CC = clang
AR = ar

NAME = ed25519_cosi
SRC = $(NAME).c
OUT = $(NAME).o
OUT_SHARED = lib$(NAME).so
OUT_STATIC = lib$(NAME).a
HEADER = $(NAME).h

TEST_NAME = ed25519_cosi_test
SRC_TEST = $(TEST_NAME).c
OUT_TEST = $(TEST_NAME)
OUT_TEST_STATIC = $(TEST_NAME)_static

TEST_SRC = ed25519_cosi_test.c

.PHONY:all clean watch

all: build-shared build-static

build:
	$(CC) $(CFLAGS) -o $(OUT) -c $(SRC) $(LDFLAGS)

build-shared: build
	$(CC) -shared -o $(OUT_SHARED) $(OUT)

build-static: build
	$(AR) rcs $(OUT_STATIC) $(OUT)

install: uninstall
	cp $(HEADER) /usr/local/include/
	cp $(OUT_STATIC) /usr/local/lib/
	cp $(OUT_SHARED) /usr/local/lib/

uninstall:
	rm -f /usr/local/include/$(HEADER)
	rm -f /usr/local/lib/$(OUT_STATIC)
	rm -f /usr/local/lib/$(OUT_SHARED)

clean:
	rm -f $(OUT)
	rm -f $(OUT_SHARED)
	rm -f $(OUT_TEST)
	rm -f $(OUT_STATIC)
	rm -f $(OUT_TEST_STATIC)

build-check: build-shared
	$(CC) $(CFLAGS) -o $(OUT_TEST) $(SRC_TEST) $(LDFLAGS) $(TEST_CFLAGS) $(TEST_LDFLAGS)

build-static-check: build-static
	$(MUSL) $(STATIC_FLAGS) $(CFLAGS) -o $(OUT_TEST_STATIC) $(SRC_TEST) $(LDFLAGS) $(TEST_CFLAGS) $(TEST_LDFLAGS)

check: build-check
	LD_LIBRARY_PATH=. ./$(OUT_TEST)

watch:
	./watch
