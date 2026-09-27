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

MODULES = 9gag activision battlenet cloudflaredns discord epicgames google \
          netflix reddit roblox spotify steam telegram twitch universal vk vrchat \
          github hf

# Слой управления перехватом. Ровно один бэкенд на сборку: выбор платформы
# делает Makefile, а не рантайм. Для Windows заменяется на
# src/netfilter/netfilter_win.c (WinDivert).
NETFILTER_SRC = src/netfilter/netfilter_linux.c

# Источники ядра (sni_relay + doh_resolve — общие для модулей на их основе)
CORE_SRC = src/main.c src/proxy/proxy.c src/dns/dns_resolve.c \
           src/dns/doh_resolve.c src/common/sni_relay.c $(NETFILTER_SRC)


.PHONY: all clean core plugs list webui rebuild desync desync-check

# ── Слой десинхронизации (src/desync) ───────────────────
# Отдельный от ядра: модуль подключает его сам и только для своих адресов.
# Требует root при запуске, но не требует пересборки ядра.
DESYNC_BIN = $(BUILD_DIR)/bin/rmf-desync

desync:
	@mkdir -p $(BUILD_DIR)/bin
	$(CC) $(CFLAGS) -o $(DESYNC_BIN) $(SRC_DIR)/desync/desync_main.c \
		$(SRC_DIR)/desync/desync.c -lpthread
	@echo "  ✅ $(DESYNC_BIN)"

# Проверка без прав и без сети: собирается ли слой и виден ли SNI в ClientHello.
desync-check:
	$(CC) $(CFLAGS) -Itest -o $(BUILD_DIR)/bin/desync-test test/desync_test.c \
		$(SRC_DIR)/desync/desync.c -lpthread
	@$(BUILD_DIR)/bin/desync-test

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

# ── Универсальный шаблон (universal использует universal.h, нестандартный inject) ──
$(PLUGS_DIR)/universal_entry.c:
	@mkdir -p $(PLUGS_DIR)
	@echo '#include "src/modules/universal/include/universal.h"' > $@
	@echo 'static void universal_inject_stub(int fd) { (void)fd; }' >> $@
	@echo '#define PLUGIN_NAME_STR "universal"' >> $@
	@echo '#define PLUGIN_INIT_FN universal_module_init' >> $@
	@echo '#define PLUGIN_INJECT_FN universal_inject_stub' >> $@
	@echo '#define PLUGIN_CLEANUP_FN universal_module_cleanup' >> $@
	@echo '#define PLUGIN_STATUS_FN universal_get_status' >> $@
	@echo '#include "src/plugin_entry.h"' >> $@

$(PLUGS_DIR)/universal.xo: $(PLUGS_DIR)/universal_entry.c $(filter-out %/test.c, $(wildcard src/modules/universal/src/*.c)) src/modules/universal/include/universal.h
	@mkdir -p $(PLUGS_DIR)
	$(CC) -shared -fPIC -I. $(CFLAGS) -o $@ $^
	@echo "  ✅ universal.xo"

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

# Makefile в зависимостях: иначе после правки рецепта make считает старый
# .xo актуальным (файл новее изменившегося .c) и молча пропускает перелинковку.
$(PLUGS_DIR)/$(1).xo: Makefile $(PLUGS_DIR)/$(1)_entry.c $(filter-out %/test.c, $(wildcard src/modules/$(2)/src/*.c)) $(wildcard src/modules/$(2)/include/*.h) $(EXTRA_SRC_$(1)) src/dns/dns_resolve.c src/dns/doh_resolve.c src/common/sni_relay.c src/common/site_bypass.c src/common/site_bypass.h src/common/site_module_impl.h src/netfilter/netfilter.h src/common/plain_relay.c src/common/plain_relay.h
	@mkdir -p $(PLUGS_DIR)
	$(CC) -shared -fPIC -I. $(CFLAGS) -o $$@ $(PLUGS_DIR)/$(1)_entry.c $(filter-out %/test.c, $(wildcard src/modules/$(2)/src/*.c)) $(EXTRA_SRC_$(1)) src/dns/dns_resolve.c src/dns/doh_resolve.c src/common/sni_relay.c $(PLUGIN_LIBS_$(1)) src/common/site_bypass.c src/common/site_probe.c src/common/plain_relay.c $(NETFILTER_SRC) -lssl -lcrypto
	@echo "  ✅ $(1).xo"
endef

# ── Генерация правил для каждого плагина ──────────────
# Общий рель и реестр IP. ВАЖНО: EXTRA_SRC_* должен быть объявлен ДО
# $(eval $(call PLUGIN_template,...)) — рецепт раскрывается в момент объявления,
# иначе переменная подставится пустой и плагин не соберётся.
EXTRA_SRC_vrchat  = src/common/claims.c
EXTRA_SRC_discord = src/common/claims.c

$(eval $(call PLUGIN_template,9gag,9gag,ninegag))
$(eval $(call PLUGIN_template,activision,activision,activision))
$(eval $(call PLUGIN_template,battlenet,battlenet,battlenet))
$(eval $(call PLUGIN_template,cloudflaredns,cloudflayerdnscom,cloudflayerdns))
$(eval $(call PLUGIN_template,discord,discord,discord))
$(eval $(call PLUGIN_template,epicgames,epicgames,epicgames))
$(eval $(call PLUGIN_template,google,google,google))
$(eval $(call PLUGIN_template,github,github,github))
$(eval $(call PLUGIN_template,hf,hf,hf))
$(eval $(call PLUGIN_template,netflix,netflix,netflix))
$(eval $(call PLUGIN_template,reddit,reddit,reddit))
$(eval $(call PLUGIN_template,roblox,robloxcom,roblox))
$(eval $(call PLUGIN_template,spotify,spotify,spotify))
$(eval $(call PLUGIN_template,steam,steam,steam))
PLUGIN_LIBS_telegram = -lssl -lcrypto -lpthread
$(eval $(call PLUGIN_template,telegram,telegram,telegram))
$(eval $(call PLUGIN_template,twitch,twitch,twitch))
$(eval $(call PLUGIN_template,vk,vk,vk))
$(eval $(call PLUGIN_template,vrchat,vrchat,vrchat))

# ── List ──────────────────────────────────────────────
list: core
	@$(RMF_BIN) list

# Список модулей одним словом в строке. Нужен, чтобы вычищать .xo удалённых
# модулей: без этого они навсегда остаются в build/bin/plugs и в списке веба.
list-modules:
	@echo $(MODULES)

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
	$(CC) $(CFLAGS) -o $(WEBUI_BIN) $(WEBUI_DIR)/server.c $(NETFILTER_SRC)
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
		$(SRC_DIR)/common/sni_relay.c $(SRC_DIR)/common/site_bypass.c \
		$(NETFILTER_SRC)
	@mkdir -p $(PLUGS_DIR)
	$(CC) -shared -fPIC -I. $(CFLAGS) -o $@ $(PLUGS_DIR)/custom_entry.c \
		$(SRC_DIR)/constructor/custom_plugin.c $(SRC_DIR)/dns/dns_resolve.c \
		$(SRC_DIR)/dns/doh_resolve.c $(SRC_DIR)/common/sni_relay.c \
		$(SRC_DIR)/common/site_bypass.c $(NETFILTER_SRC) -lcrypto -lpthread
	@echo "  ✅ custom.xo"

custom: $(CUSTOM_PLUGIN)
