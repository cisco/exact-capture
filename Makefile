PREFIX=/usr/local
CC=cc
INCLUDES=-Ilibs -Isrc -I.
LDFLAGS=libs/libchaste/libchaste.a
GLOBAL_CFLAGS=-g -std=c99 -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=700 -fPIC -Wno-missing-field-initializers -Wno-missing-braces
RELEASE_CFLAGS=$(INCLUDES) $(GLOBAL_CFLAGS) -O3 -Wall -DNDEBUG -DNOIFASSERT
ASSERT_CFLAGS=$(INCLUDES) $(GLOBAL_CFLAGS) -O3 -Wall -DNDEBUG
DEBUG_CFLAGS=$(INCLUDES) $(GLOBAL_CFLAGS) -Werror -Wall -Wextra -pedantic
BIN=bin/exact-capture bin/exact-pcap-extract bin/exact-pcap-parse bin/exact-pcap-match

EXACTCAP_SRCS=$(wildcard src/*.c) $(wildcard src/**/*.c)
EXACTCAP_HDRS=$(wildcard src/*.h) $(wildcard src/**/*.h) 
LIBCHASTE_HDRS=$(wildcard libs/chaste/*.h) $(wildcard libs/chaste/**/*.h) 
BUFF_SRC=tools/data_structs/buff.c

all: CFLAGS = $(RELEASE_CFLAGS)
all: $(BIN)

assert: CFLAGS = $(ASSERT_CFLAGS)
assert: $(BIN)

debug: CFLAGS = $(DEBUG_CFLAGS)
debug: $(BIN)

bin/exact-capture: $(EXACTCAP_SRCS) $(EXACTCAP_HDRS) $(LIBCASHTE_HDRS) 	
	mkdir -p bin
	$(CC) $(CFLAGS) $(EXACTCAP_SRCS) $(LDFLAGS) -lm -lexanic -lpthread -lrt -o $@ 

bin/exact-pcap-parse: tools/exact-pcap-parse.c $(EXACTCAP_HDRS) $(LIBCAHSTE_HDRS)
	mkdir -p bin
	$(CC) $(CFLAGS) tools/exact-pcap-parse.c $(LDFLAGS) -o $@

bin/exact-pcap-match: tools/exact-pcap-match.c $(EXACTCAP_HDRS) $(LIBCAHSTE_HDRS)
	mkdir -p bin
	$(CC) $(CFLAGS) tools/exact-pcap-match.c $(LDFLAGS) -o $@

bin/exact-pcap-extract: $(BUFF_SRC) tools/exact-pcap-extract.c $(EXACTCAP_HDRS) $(LIBCAHSTE_HDRS)
	$(CC) $(CFLAGS) $(BUFF_SRC) tools/exact-pcap-extract.c $(LDFLAGS) -o $@

install: all
	install -d $(PREFIX)/bin
	install -m 0755 -D $(BIN) $(PREFIX)/bin

uninstall:
	rm -f $(foreach file,$(BIN),$(PREFIX)/bin/$(file))

.PHONY: docs
docs:
	$(MAKE) -C docs/

clean:
	rm -rf bin/*
	$(MAKE) -C docs/ clean

