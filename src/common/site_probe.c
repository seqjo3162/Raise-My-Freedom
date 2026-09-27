#include "src/common/site_probe.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <fcntl.h>

static unsigned int g_probe_mark;

void site_probe_set_mark(unsigned int mark) { g_probe_mark = mark; }

static int dial(const char *ip, int port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    // Проба ОБЯЗАНА быть помеченной. Иначе она измеряет собственный рель
    // модуля, а не путь до сайта: REDIRECT на перехватываемый диапазон
    // перехватывает и проверку, accept реля отвечает мгновенно, и адрес,
    // который на самом деле зарезан провайдером, выглядит живым. Именно так
    // в пин VRChat попал 143.204.238.54 — и аватары показывали Error.
    // Метка совпадает с RETURN-правилом модуля, которое стоит выше REDIRECT.
    if (g_probe_mark) {
        setsockopt(fd, SOL_SOCKET, SO_MARK, &g_probe_mark, sizeof(g_probe_mark));
    }
    if (fd < 0) return -1;
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { close(fd); return -1; }

    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
    if (rc != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc != 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) { close(fd); return -1; }
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

int site_probe_tcp(const char *ip, int port, int timeout_ms) {
    int fd = dial(ip, port, timeout_ms);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

// ClientHello собирает OpenSSL (настоящий, а не самодельный — edge отбрасывает
// выдуманный), а вердикт ставится по сырому сокету: пришли байты на ClientHello
// или нет. Любой ответ означает, что нас видят; тишина — домен режут. Ошибки
// самого TLS здесь ни при чём и вводили бы в заблуждение.
int site_probe_sni(const char *ip, const char *hostname, int timeout_ms) {
    int fd = dial(ip, 443, timeout_ms);
    if (fd < 0) return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return -1; }
    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return -1; }
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_tlsext_host_name(ssl, hostname);
    SSL_set_connect_state(ssl);
    ERR_clear_error();
    SSL_do_handshake(ssl);                       // наполняет wbio

    BUF_MEM *bm = NULL;
    BIO_get_mem_ptr(wbio, &bm);
    int sent = 0;
    if (bm && bm->length > 0) {
        const unsigned char *p = (const unsigned char *)bm->data;
        size_t left = bm->length;
        while (left > 0) {
            ssize_t s = send(fd, p, left, 0);
            if (s > 0) { p += s; left -= (size_t)s; sent += (int)s; continue; }
            if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                if (poll(&pfd, 1, timeout_ms) <= 0) break;
                continue;
            }
            if (s < 0 && errno == EINTR) continue;
            break;
        }
    }
    // BIO прикреплены к ssl, освобождает их SSL_free — руками трогать нельзя
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    if (sent == 0) { close(fd); return 0; }

    unsigned char buf[512];
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr <= 0) { close(fd); return 0; }          // тишина
    ssize_t r = recv(fd, buf, sizeof(buf), 0);
    close(fd);
    return r > 0 ? 1 : 0;
}

// Полноценное TLS-рукопожатие с проверкой имени в сертификате. Нужна, чтобы
// отличить «домен режут по имени» от «адрес достался чужому серверу».
//
// site_probe_sni для обоих случаев даёт 1: и зарезанный по имени домен
// отвечает байтами, и чужой сервер завершает рукопожатие. Разница видна
// только в сертификате. Именно это портило Hugging Face: закреплённый
// 3.161.105.31 молча перешёл Amazon'у, отдавал CN=dp-contacts-opf.amazon.com,
// и считался живым, пока CDN файлов не начал отдавать мусор вместо моделей.
int site_probe_cert_ok(const char *ip, const char *hostname, int timeout_ms) {
    if (!ip || !hostname) return -1;
    int fd = dial(ip, 443, timeout_ms);
    if (fd < 0) return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return -1; }
    // Верификацию на время рукопожатия выключаем намеренно. Если включить
    // SSL_VERIFY_PEER, OpenSSL обрывает рукопожатие сам, и «сервер отвечает,
    // но имя не то» становится неотличимо от «сервер молчит, домен режут» —
    // а это ровно два разных случая, которые надо различать.
    // Имя проверяем сами, уже по факту полученного сертификата.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return -1; }
    SSL_set_fd(ssl, fd);
    // SNI обязателен. CloudFront держит на одном адресе много доменов и
    // различает их именно по SNI: без него сервер либо отвечает сертификатом
    // чужого домена, либо обрывает соединение, и проверка имени становится
    // бессмысленной. Именно из-за отсутствия SNI адреса CloudFront, где домен
    // на самом деле отвечает, выглядели как заблокированные, и выбор уходил
    // на закрытый адрес.
    SSL_set_tlsext_host_name(ssl, hostname);
    SSL_set_connect_state(ssl);

    // Рукопожатие многозаходное, и на блокирующем сокете оно упирается в
    // poll: сначала нужно дождаться writability, потом handshake читает ответ и
    // снова пишет. Поэтому сокет неблокирующий, а цикл крутит
    // SSL_do_handshake, подпитываясь событиями, пока не сложится или не выйдет
    // время.
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    int done = 0;
    for (;;) {
        ERR_clear_error();
        int r = SSL_do_handshake(ssl);
        if (r == 1) { done = 1; break; }
        int err = SSL_get_error(ssl, r);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) break;
        struct pollfd pfd = { .fd = fd,
            .events = (short)((err == SSL_ERROR_WANT_READ ? POLLIN : 0) |
                              (err == SSL_ERROR_WANT_WRITE ? POLLOUT : 0)) };
        if (poll(&pfd, 1, timeout_ms) <= 0) break;
    }

    int rc = -1;
    if (done) {
        // Рукопожатие прошло — сервер настоящий. Осталось выяснить, его это
        // имя или чужое. Сертификат покрывает и точное имя, и wildcard.
        X509 *cert = SSL_get1_peer_certificate(ssl);
        if (cert) {
            rc = X509_check_host(cert, hostname, strlen(hostname),
                                 X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, NULL) == 1
                 ? 1 : 0;
            X509_free(cert);
        }
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return rc;
}
