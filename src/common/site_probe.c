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
#include <fcntl.h>

static int dial(const char *ip, int port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
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
