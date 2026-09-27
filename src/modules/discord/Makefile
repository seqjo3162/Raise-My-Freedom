# discord — юнит-тесты модуля. Сеть и root не нужны для основной части.
#
#   make        — собрать тест-бинарник
#   make test   — собрать и прогнать
#   make clean  — убрать артефакты
#
# Раньше рецепт линковал src/relay.c, которого в проекте нет, и звал удалённое
# API (discord_relay_start/running/stop). Тест не собирался никогда. Теперь он
# включает сам модуль и проверяет то, что реально работает.

CC ?= gcc
CFLAGS ?= -std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra

HERE := $(dir $(lastword $(MAKEFILE_LIST)))
ROOT := $(HERE)../../..
BIN := $(HERE)build/discord_test

# test.c включает src/discord_module.c сам (нужен доступ к static-хелперам),
# поэтому в линковку модуль не идёт второй раз.
SRC := $(ROOT)/src/common/sni_relay.c \
       $(ROOT)/src/common/claims.c \
       $(ROOT)/src/common/site_probe.c \
       $(ROOT)/src/dns/dns_resolve.c \
       $(ROOT)/src/dns/doh_resolve.c \
       $(ROOT)/src/netfilter/netfilter_linux.c

DEPS := $(HERE)test/test.c $(HERE)src/discord_module.c $(SRC) $(HERE)include/header.h \
        $(ROOT)/src/common/sni_relay.h $(ROOT)/src/common/claims.h \
        $(ROOT)/src/common/site_probe.h $(ROOT)/src/dns/dns_resolve.h \
        $(ROOT)/src/dns/doh_resolve.h

.PHONY: all test clean

all: $(BIN)

$(BIN): $(DEPS)
	mkdir -p $(HERE)build
	$(CC) $(CFLAGS) -I$(ROOT) -o $@ $(HERE)test/test.c $(SRC) -lssl -lcrypto

test: $(BIN)
	$(BIN)

clean:
	rm -rf $(HERE)build
