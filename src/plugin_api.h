#ifndef PLUGIN_API_H
#define PLUGIN_API_H

#include <string.h>
#include <ctype.h>

// rmf Plugin API v1.0
//
// Каждый плагин (.xo файл) должен экспортировать 4 функции:
//   const char* plug_name(void);         - имя плагина
//   void plug_init(void* config);        - инициализация
//   void plug_inject(int fd);            - инъекция (обход DPI)
//   void plug_cleanup(void);             - очистка
//
// Плагины могут вызывать dns_resolve_udp() из ядра (экспортируется через -rdynamic).

const char* plug_name(void);
void plug_init(void* config);
void plug_inject(int fd);
void plug_cleanup(void);
const char* plug_status(void);

static inline int plugin_name_valid(const char *name) {
    if (!name || !*name || strlen(name) > 64) return 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++)
        if (!isalnum(*p) && *p != '_' && *p != '-') return 0;
    return 1;
}

static inline const char *plugin_canonical_name(const char *name) {
    static const char *const aliases[][2] = {
        {"xcom", "x"},
        {"twitter", "x"},
        {"robloxcom", "roblox"},
        {"soundcloudcom", "soundcloud"},
        {"cloudflayerdnscom", "cloudflaredns"},
        {"speedtestnet", "speedtestbyookla"}
    };

    if (!name) return "";
    for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++)
        if (strcmp(name, aliases[i][0]) == 0) return aliases[i][1];
    return name;
}

#endif // PLUGIN_API_H
