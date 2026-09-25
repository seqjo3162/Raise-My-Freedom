# rmf Makefile v3.0 — Plugin Architecture
# Ядро: main.c + proxy.c + dns_resolve.c (-rdynamic)
# Плагины: каждый модуль → .xo shared library в plugs/

CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -O2 -I.
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I.

SRC_DIR = src
BUILD_DIR = build
WEBUI_DIR = webui
PLUGS_DIR = $(BUILD_DIR)/bin/plugs

RMF_BIN = $(BUILD_DIR)/bin/rmf
WEBUI_BIN = $(BUILD_DIR)/bin/rmf-web

MODULES = activision battlenet cloudflaredns discord electronicarts epicgames github google \
          roblox soundcloud speedtestbyookla spotify steam telegram twitch vrchat x

# Источники ядра (sni_relay + doh_resolve — общие для google/x/speedtest)
CORE_SRC = src/main.c src/proxy/proxy.c src/dns/dns_resolve.c \
           src/dns/doh_resolve.c src/common/sni_relay.c

.PHONY: all clean core plugs list webui rebuild

all: core plugs webui

# ── Ядро ──────────────────────────────────────────────
core:
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  🚀 rmf Core Build"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@mkdir -p $(BUILD_DIR)/bin
	$(CC) -std=gnu11 $(CFLAGS) -rdynamic -o $(RMF_BIN) $(CORE_SRC) -ldl
	@echo "✅ Core: $(RMF_BIN)"

# ── Все плагины ──────────────────────────────────────
plugs: $(addprefix $(PLUGS_DIR)/,$(addsuffix .xo,$(MODULES)))
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  ✅ All plugins built → $(PLUGS_DIR)/"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Шаблон плагина ────────────────────────────────────
# $(1) = имя плагина
# $(2) = папка исходников
# EXTRA_$(1) — дополнительные .c (например sni_relay) для отдельных плагинов
define PLUGIN_template

$(PLUGS_DIR)/$(1)_entry.c:
	@mkdir -p $(PLUGS_DIR)
	@echo '#include "src/modules/$(2)/include/header.h"' > $$@
	@echo '#define PLUGIN_NAME_STR "$(1)"' >> $$@
	@echo '#define PLUGIN_INIT_FN $(3)_module_init' >> $$@
	@echo '#define PLUGIN_INJECT_FN $(3)_module_inject' >> $$@
	@echo '#define PLUGIN_CLEANUP_FN $(3)_module_cleanup' >> $$@
	@echo '#define PLUGIN_STATUS_FN $(3)_get_status' >> $$@
	@echo '#include "src/plugin_entry.h"' >> $$@

$(PLUGS_DIR)/$(1).xo: $(PLUGS_DIR)/$(1)_entry.c $(filter-out %/test.c, $(wildcard src/modules/$(2)/src/*.c)) $(wildcard src/modules/$(2)/include/*.h) $(EXTRA_SRC_$(1)) src/dns/dns_resolve.c src/dns/doh_resolve.c src/common/sni_relay.c src/common/site_bypass.c src/common/site_bypass.h src/common/sni_relay.h src/common/site_module_impl.h
	@mkdir -p $(PLUGS_DIR)
	$(CC) -shared -fPIC -I. $(CFLAGS) -o $$@ $(PLUGS_DIR)/$(1)_entry.c $(filter-out %/test.c, $(wildcard src/modules/$(2)/src/*.c)) $(EXTRA_SRC_$(1)) src/dns/dns_resolve.c src/dns/doh_resolve.c src/common/sni_relay.c $(PLUGIN_LIBS_$(1)) src/common/site_bypass.c -lcrypto
	@echo "  ✅ $(1).xo"
endef

# ── Генерация правил для каждого плагина ──────────────
PLUGIN_LIBS_telegram = -lcrypto -lpthread
$(eval $(call PLUGIN_template,activision,activision,activision))
$(eval $(call PLUGIN_template,battlenet,battlenet,battlenet))
$(eval $(call PLUGIN_template,cloudflaredns,cloudflayerdnscom,cloudflayerdns))
$(eval $(call PLUGIN_template,discord,discord,discord))
$(eval $(call PLUGIN_template,electronicarts,electronicarts,electronicarts))
$(eval $(call PLUGIN_template,epicgames,epicgames,epicgames))
$(eval $(call PLUGIN_template,github,github,github))
$(eval $(call PLUGIN_template,google,google,google))
$(eval $(call PLUGIN_template,roblox,robloxcom,roblox))
$(eval $(call PLUGIN_template,soundcloud,soundcloudcom,soundcloud))
$(eval $(call PLUGIN_template,speedtestbyookla,speedtestbyookla,speedtestbyookla))
$(eval $(call PLUGIN_template,spotify,spotify,spotify))
$(eval $(call PLUGIN_template,steam,steam,steam))
$(eval $(call PLUGIN_template,telegram,telegram,telegram))
$(eval $(call PLUGIN_template,twitch,twitch,twitch))
$(eval $(call PLUGIN_template,vrchat,vrchat,vrchat))
$(eval $(call PLUGIN_template,x,xcom,xcom))

# ── List ──────────────────────────────────────────────
list: core
	@$(RMF_BIN) list

# ── Clean ─────────────────────────────────────────────
clean:
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  🧹 Clean"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	rm -f $(RMF_BIN) $(WEBUI_BIN)
	rm -f $(PLUGS_DIR)/*.xo $(PLUGS_DIR)/*_entry.c
	@echo "✅ Done"

rebuild: clean all

# ── Web UI ─────────────────────────────────────────────
webui:
	@mkdir -p $(BUILD_DIR)/bin
	$(CC) $(CFLAGS) -o $(WEBUI_BIN) $(WEBUI_DIR)/server.c
	@echo "  ✅ $(WEBUI_BIN)"

# ── Конструктор: валидатор и раннер ────────────────────
VALIDATE_BIN = $(BUILD_DIR)/bin/mz-validate
CUSTOM_PLUGIN = $(PLUGS_DIR)/custom.xo

validate:
	@mkdir -p $(BUILD_DIR)/bin
	$(CC) $(CFLAGS) -o $(VALIDATE_BIN) $(SRC_DIR)/constructor/validate.c \
		$(SRC_DIR)/dns/dns_resolve.c $(SRC_DIR)/dns/doh_resolve.c
	@echo "  ✅ $(VALIDATE_BIN)"

$(PLUGS_DIR)/custom_entry.c:
	@mkdir -p $(PLUGS_DIR)
	@echo '#include "src/constructor/custom_plugin.h"' > $@
	@echo '#define PLUGIN_NAME_STR "custom"' >> $@
	@echo '#define PLUGIN_INIT_FN custom_init' >> $@
	@echo '#define PLUGIN_INJECT_FN custom_inject' >> $@
	@echo '#define PLUGIN_CLEANUP_FN custom_cleanup' >> $@
	@echo '#define PLUGIN_STATUS_FN custom_get_status' >> $@
	@echo '#include "src/plugin_entry.h"' >> $@

# Плагин-раннер: один бинарник запускает любую спецификацию из конструктора
$(CUSTOM_PLUGIN): $(PLUGS_DIR)/custom_entry.c $(SRC_DIR)/constructor/custom_plugin.c \
		$(SRC_DIR)/dns/dns_resolve.c $(SRC_DIR)/dns/doh_resolve.c \
		$(SRC_DIR)/common/sni_relay.c $(SRC_DIR)/common/site_bypass.c
	@mkdir -p $(PLUGS_DIR)
	$(CC) -shared -fPIC -I. $(CFLAGS) -o $@ $(PLUGS_DIR)/custom_entry.c \
		$(SRC_DIR)/constructor/custom_plugin.c $(SRC_DIR)/dns/dns_resolve.c \
		$(SRC_DIR)/dns/doh_resolve.c $(SRC_DIR)/common/sni_relay.c \
		$(SRC_DIR)/common/site_bypass.c -lcrypto -lpthread
	@echo "  ✅ custom.xo"

custom: $(CUSTOM_PLUGIN)
