# discord — модуль обхода ТСПУ: честный DNS + SNI-split relay (TLS record-фрагментация)
#
#   make        — собрать тест-бинарник
#   make test   — собрать и прогнать диагностику (self/DNS/TLS/relay/HTTP/throttle)
#   make clean  — убрать артефакты

CC ?= gcc
CFLAGS ?= -std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra

HERE := $(dir $(lastword $(MAKEFILE_LIST)))
ROOT := $(HERE)../../..
BIN := $(HERE)build/discord_test

.PHONY: all test clean

all: $(BIN)

$(BIN): $(HERE)src/discord_module.c $(HERE)src/relay.c $(HERE)test/test.c $(HERE)include/header.h $(ROOT)/src/dns/dns_resolve.c $(ROOT)/src/dns/doh_resolve.c $(ROOT)/src/dns/dns_resolve.h $(ROOT)/src/dns/doh_resolve.h
	mkdir -p $(HERE)build
	$(CC) $(CFLAGS) -I$(ROOT) -o $@ \
		$(HERE)src/discord_module.c $(HERE)src/relay.c $(HERE)test/test.c \
		$(ROOT)/src/dns/dns_resolve.c $(ROOT)/src/dns/doh_resolve.c

test: $(BIN)
	$(BIN)

clean:
	rm -rf $(HERE)build
