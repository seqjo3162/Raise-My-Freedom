#ifndef NETFILTER_H
#define NETFILTER_H

#include <stdbool.h>
#include <stdint.h>

// Платформенно-независимый слой управления перехватом пакетов.
//
// Выбор бэкенда происходит НА ЭТАПЕ СБОРКИ, а не в рантайме: в Makefile
// подключается ровно один из netfilter_linux.c / netfilter_win.c. Отдельный
// бинарник — одна платформа, поэтому код нигде не спрашивает «какая у меня ОС».
// Всё, что выше этого слоя, работает только через nf_* и не знает, что снизу
// iptables, а что WinDivert.

#ifdef __cplusplus
extern "C" {
#endif

// Имя активного бэкенда для логов и веба: "iptables" или "windivert".
const char *nf_backend_name(void);

// Доступен ли бэкенд в текущей среде (на Linux нужен root, на Windows — драйвер).
bool nf_available(void);

int  nf_init(void);
void nf_shutdown(void);

// Цепочки и точки входа.
int nf_chain_create(const char *chain);
int nf_chain_flush(const char *chain);
int nf_chain_destroy(const char *chain);
int nf_hook_output(const char *chain, int pos);
int nf_hook_prerouting(const char *chain);

// Пропуск собственного трафика бэкенда: без него пакеты, которые шлёт сам
// обход, снова попадут в правила и замкнутся в петлю. На Linux это SO_MARK,
// на Windows — фильтрация по PID.
int nf_exempt_own_traffic(const char *chain);

// Пометить сокет, чтобы его трафик не попал в собственные правила. Модули
// используют разные mark в диапазоне, который exempt_own_traffic
// пропускает целиком, поэтому конкретное значение можно задавать явно.
int nf_mark_socket(int fd);
int nf_mark_socket_as(int fd, unsigned int mark);

// Перехват трафика. dest — одиночный адрес или CIDR (например 162.159.128.0/18).
int nf_tcp_redirect(const char *chain, const char *dest, int dport, int to_port);
int nf_udp_redirect(const char *chain, const char *dest, int dport, int to_port);
int nf_tcp_deny(const char *chain, const char *dest, int dport);
int nf_udp_deny(const char *chain, const char *dest, int dport);

// Перехват DNS. С доменом — правило по имени (--hex-string), без домена —
// перехват всего UDP/53. Второе опасно для всей системы и должно
// использоваться осознанно.
int nf_dns_redirect(const char *chain, const char *domain, int to_port);
int nf_dns_redirect_all(const char *chain, int to_port);

// Удалить все цепочки, созданные через nf_chain_create. Список ведётся в
// runtime-файле, поэтому не зависит от того, какие модули сейчас запущены,
// и переживает перезапуск процесса.
int nf_cleanup_all(void);

// Путь к runtime-реестру цепочек. Файл можно удалять: он пересоздаётся.
const char *nf_registry_path(void);

#ifdef __cplusplus
}
#endif

#endif
