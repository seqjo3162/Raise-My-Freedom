// Windows-бэкенд слоя netfilter: WinDivert (NST).
//
// Заглушка: контракт зафиксирован, реальная реализация впереди. Файл не входит
// в сборку на Linux — см. NETFILTER_SRC в Makefile.
//
// Ключевое отличие от Linux-бэкенда: SO_MARK на Windows нет, поэтому
// «пропустить собственный трафик» реализуется фильтрацией по PID процесса,
// что точнее маркировки пакетов.

#ifdef _WIN32

#include "netfilter.h"
#include <windows.h>

const char *nf_backend_name(void) { return "windivert"; }

// Требуется установленный и запущенный сервис WinDivert (NST).
bool nf_available(void) {
    SC_HANDLE sc = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!sc) return false;
    SC_HANDLE svc = OpenServiceA(sc, "WinDivert", SERVICE_QUERY_STATUS);
    bool ok = svc != NULL;
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(sc);
    return ok;
}

int  nf_init(void) { return nf_available() ? 0 : -1; }
void nf_shutdown(void) {}

// Каждая цепочка Linux превращается в набор фильтров WinDivert, а не в одну
// сущность, поэтому функции ниже возвращают -1 до появления бэкенда.
int nf_chain_create(const char *chain) { (void)chain; return -1; }
int nf_chain_flush(const char *chain) { (void)chain; return -1; }
int nf_chain_destroy(const char *chain) { (void)chain; return -1; }
int nf_hook_output(const char *chain, int pos) { (void)chain; (void)pos; return -1; }
int nf_hook_prerouting(const char *chain) { (void)chain; return -1; }
int nf_exempt_own_traffic(const char *chain) { (void)chain; return -1; }

// На Windows PID известен из процесса, помечать сокеты не нужно.
int nf_mark_socket(int fd) { (void)fd; return 0; }
int nf_mark_socket_as(int fd, unsigned int mark) { (void)fd; (void)mark; return 0; }

int nf_tcp_redirect(const char *chain, const char *dest, int dport, int to_port) {
    (void)chain; (void)dest; (void)dport; (void)to_port; return -1;
}
int nf_udp_redirect(const char *chain, const char *dest, int dport, int to_port) {
    (void)chain; (void)dest; (void)dport; (void)to_port; return -1;
}
int nf_tcp_deny(const char *chain, const char *dest, int dport) {
    (void)chain; (void)dest; (void)dport; return -1;
}
int nf_udp_deny(const char *chain, const char *dest, int dport) {
    (void)chain; (void)dest; (void)dport; return -1;
}
int nf_dns_redirect(const char *chain, const char *domain, int to_port) {
    (void)chain; (void)domain; (void)to_port; return -1;
}
int nf_dns_redirect_all(const char *chain, int to_port) {
    (void)chain; (void)to_port; return -1;
}
int nf_cleanup_all(void) { return -1; }
const char *nf_registry_path(void) { return ""; }

#endif // _WIN32
