#ifndef CUSTOM_PLUGIN_H
#define CUSTOM_PLUGIN_H

// Прототипы раннера конструктора. Имена не совпадают с plug_*,
// которые генерирует src/plugin_entry.h, иначе получится рекурсия.

void custom_init(void *config);
void custom_inject(int fd);
void custom_cleanup(void);
const char *custom_get_status(void);

#endif // CUSTOM_PLUGIN_H
