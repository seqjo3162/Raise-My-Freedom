#ifndef RMF_SITE_PROBE_H
#define RMF_SITE_PROBE_H

// Проверка достижимости сайта. Нужна, чтобы модуль сам выбирал режим, а не
// полагался на ручную настройку:
//
//   site_probe_tcp — доходит ли TCP до адреса. Если нет, адрес отброшен
//                   провайдером, рель тут не поможет в принципе.
//   site_probe_sni — отвечает ли сервер на ClientHello с этим SNI. Молчание
//                   означает, что режут по имени домена, и тогда нужен рель
//                   с разрывом SNI. Любой ответ (в том числе alert) означает,
// что имя видно и рель не нужен.

int site_probe_tcp(const char *ip, int port, int timeout_ms);

// 1 — сервер ответил (SNI виден), 0 — тишина (SNI режут), -1 — нет соединения
int site_probe_sni(const char *ip, const char *hostname, int timeout_ms);

#endif
