#ifndef PLUGIN_ENTRY_H
#define PLUGIN_ENTRY_H

// Макросы определяются перед #include этого файла:
//   PLUGIN_NAME_STR  — строка имени плагина
//   PLUGIN_INIT_FN   — функция init модуля
//   PLUGIN_INJECT_FN — функция inject модуля
//   PLUGIN_CLEANUP_FN — функция cleanup модуля

const char* plug_name(void) { return PLUGIN_NAME_STR; }
void plug_init(void* config) { PLUGIN_INIT_FN(config); }
void plug_inject(int fd) { PLUGIN_INJECT_FN(fd); }
void plug_cleanup(void) { PLUGIN_CLEANUP_FN(); }
#ifdef PLUGIN_STATUS_FN
const char* plug_status(void) { return PLUGIN_STATUS_FN(); }
#else
const char* plug_status(void) { return "Active"; }
#endif

#endif // PLUGIN_ENTRY_H
