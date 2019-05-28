ifeq ($(origin CC),default)
	CC = gcc
endif
AR := ar

ROOT := .
OBJ := $(ROOT)
SRC := $(ROOT)
TEST_SRC := $(ROOT)/tests
TEST_OBJ := $(ROOT)/tests
GLOBAL_LIB = /usr/local/lib
GLOBAL_INCLUDE = /usr/local/include
INSTALL_LIB ?= $(GLOBAL_LIB)
INSTALL_INCLUDE ?= $(GLOBAL_INCLUDE)

NAME := ed25519_cosi
SOURCES := $(wildcard $(SRC)/*.c)
HEADERS := $(wildcard $(SRC)/*.h)
TEST_SOURCES := $(wildcard $(TEST_SRC)/*.c)

OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES))
TEST_OBJECTS := $(patsubst $(TEST_SRC)/%.c, $(TEST_OBJ)/%.o, $(TEST_SOURCES))

SHARED := $(OBJ)/lib$(NAME).so
ARCHIVE := $(OBJ)/lib$(NAME).a

CFLAGS=-Wall -I$(GLOBAL_INCLUDE) -I$(ROOT) -fPIC
LDFLAGS=

TEST_CFLAGS=
TEST_LDFLAGS=-L$(ROOT) -lsodium -lcheck -pthread -lrt -lm -lsubunit -led25519_cosi

.PHONY:all clean watch

all: build-shared build-archive

build: $(OBJECTS)

check: $(patsubst $(TEST_OBJ)/%.o, check-%, $(TEST_OBJECTS))

build-shared: $(SHARED)

build-archive: $(ARCHIVE)

build-tests: $(TEST_OBJECTS)

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -o $@ -c $< $(LDFLAGS)

$(SHARED): $(OBJECTS)
	$(CC) -shared -o $@ $<

$(ARCHIVE): $(OBJECTS)
	$(AR) rcs $@ $<

install: uninstall build-shared build-archive
	cp $(HEADERS) $(INSTALL_INCLUDE)
	cp $(SHARED) $(INSTALL_LIB)
	cp $(ARCHIVE) $(INSTALL_LIB)

uninstall:
	rm -f $(patsubst $(SRC)/%.h, $(INSTALL_INCLUDE)/%.h, $(HEADERS))
	rm -f $(patsubst $(OBJ)/%.so, $(INSTALL_LIB)/%.so, $(SHARED))
	rm -f $(patsubst $(OBJ)/%.a, $(INSTALL_LIB)/%.a, $(ARCHIVE))

clean:
	rm -f $(OBJECTS)
	rm -f $(SHARED)
	rm -f $(ARCHIVE)

$(TEST_OBJ)/%.o: $(TEST_SRC)/%.c $(SHARED)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(TEST_CFLAGS) $(TEST_LDFLAGS)

check-%: $(TEST_OBJ)/%.o
	LD_LIBRARY_PATH=$(ROOT) $<

clean-tests:
	rm -f $(TEST_OBJECTS)

watch:
	@./.watch
