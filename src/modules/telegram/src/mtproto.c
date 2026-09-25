// MTProto proxy (MTProxy) для модуля telegram.
//
// Протокол по эталону alexbers/mtprotoproxy / 9seconds/mtg.
// Ни RSA, ни X25519, ни AES-IGE здесь нет: схема симметричная, на общем
// 16-байтном секрете пользователя и AES-256-CTR.
//
//   клиент -> прокси:  64-байтовый кадр
//        [0..7]    случайный шум
//        [8..55]   prekey(32) + iv(16)          — идут открытыми
//        [56..59]  маркер протокола              — зашифрованы
//        [60..61]  индекс ДЦ (знаковый int16)   — зашифрован
//        [62..63]  хвост                        — зашифрован
//   dec_key = SHA256(prekey + secret), шифр AES-256-CTR с iv из prekey+iv.
//   Для отправки берётся перевёрнутый prekey+iv и свой SHA256.
//
// Режимы: abridged (0xefefefef), intermediate (0xeeeeeeee), secure (0xdddddddd).
// fake-TLS: клиент присылает ClientHello с HMAC-SHA256 от секрета, прокси
// проверяет подпись и отвечает поддельным ServerHello — сертификат не нужен.
//
// Пул: TG_POOL_X6 соединений по IPv6 и TG_POOL_X4 по IPv4 к ДЦ Telegram.

#include "src/modules/telegram/include/header.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>
#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#define TG_POOL_X6        6
#define TG_POOL_X4        4
#define TG_HANDSHAKE_LEN  64
#define TG_SKIP_LEN       8
#define TG_PREKEY_LEN     32
#define TG_IV_LEN         16
#define TG_KEY_LEN        32
#define TG_PROTO_TAG_POS  56
#define TG_DCIDX_POS      60
#define TG_DC_PORT        443
#define TG_BUFSIZE        65536
#define TG_HANDSHAKE_TMO  15
#define TG_READ_TMO       60

static const unsigned char TAG_ABRIDGED[4]    = {0xef, 0xef, 0xef, 0xef};
static const unsigned char TAG_INTERMEDIATE[4] = {0xee, 0xee, 0xee, 0xee};
static const unsigned char TAG_SECURE[4]       = {0xdd, 0xdd, 0xdd, 0xdd};

// ДЦ Telegram. dc_idx = |значение| - 1
static const char *DC_V4[5] = {
    "149.154.175.50", "149.154.161.144", "149.154.175.100",
    "91.108.4.136",   "91.108.56.183"
};
static const char *DC_V6[5] = {
    "2001:b28:f23d:f001::a", "2001:67c:04e8:f002::a", "2001:b28:f23d:f003::a",
    "2001:67c:04e8:f004::a", "2001:67c:04e8:f005::a"
};

// секрет пользователя: 16 байт. В приложении Telegram вводится как 32 hex-символа
static unsigned char g_secret[16];
static int g_secret_ready = 0;

static void secret_set_hex(const char *hex) {
    size_t n = hex ? strlen(hex) : 0;
    for (size_t i = 0; i < 16 && i * 2 + 1 < n; i++) {
        char b[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        g_secret[i] = (unsigned char)strtoul(b, NULL, 16);
    }
    g_secret_ready = 1;
}

  static void secret_init(void) {
      if (g_secret_ready) return;
      // значение по умолчанию; переопределяется переменной TG_PROXY_SECRET (32 hex)
      const char *env = getenv("TG_PROXY_SECRET");
      if (env && strlen(env) >= 32) {
          char b[33];
          memcpy(b, env, 32); b[32] = 0;
          secret_set_hex(b);
      } else {
          secret_set_hex("00000000000000000000000000000000");
      }
  }

  // Задаёт секрет извне (например, прочитанный из webui/telegram.conf).
  // Без этого настройка из веб-интерфейса не доходила до прокси.
  void telegram_proxy_set_secret(const char *hex) {
      if (!hex) return;
      size_t n = strlen(hex);
      if (n < 32) return;
      for (int i = 0; i < 16; i++) {
          if (!isxdigit((unsigned char)hex[i * 2]) || !isxdigit((unsigned char)hex[i * 2 + 1])) return;
      }
      char b[33];
      memcpy(b, hex, 32);
      b[32] = '\0';
      secret_set_hex(b);
  }

// ────────────────────────── криптопримитивы ──────────────────────────

typedef struct { EVP_CIPHER_CTX *ctx; unsigned char key[32], ctr[16]; } tg_ctr;

static int ctr_new(tg_ctr *c, const unsigned char key[32], const unsigned char iv[16]) {
    c->ctx = EVP_CIPHER_CTX_new();
    if (!c->ctx) return -1;
    memcpy(c->key, key, 32);
    memcpy(c->ctr, iv, 16);
    if (EVP_EncryptInit_ex(c->ctx, EVP_aes_256_ctr(), NULL, c->key, c->ctr) != 1) {
        EVP_CIPHER_CTX_free(c->ctx); c->ctx = NULL; return -1;
    }
    return 0;
}

static void ctr_free(tg_ctr *c) {
    if (c->ctx) EVP_CIPHER_CTX_free(c->ctx);
    c->ctx = NULL;
    OPENSSL_cleanse(c, sizeof(*c));
}

// AES-256-CTR симметричен, поэтому шифрование и расшифровка — одна операция
static int ctr_apply(tg_ctr *c, const unsigned char *in, unsigned char *out, int n) {
    int outl = 0, total = 0;
    if (n <= 0) return 0;
    if (EVP_EncryptUpdate(c->ctx, out, &outl, in, n) != 1) return -1;
    total = outl;
    if (EVP_EncryptFinal_ex(c->ctx, out + total, &outl) != 1) return -1;
    return total + outl;
}

static void sha256_buf(const unsigned char *in, size_t n, unsigned char out[32]) {
    unsigned int len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, n);
    EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);
}

// ключ = SHA256(prekey + secret)
static void derive_key(const unsigned char *prekey, unsigned char key[32]) {
    unsigned char buf[TG_PREKEY_LEN + 16];
    memcpy(buf, prekey, TG_PREKEY_LEN);
    memcpy(buf + TG_PREKEY_LEN, g_secret, 16);
    sha256_buf(buf, sizeof(buf), key);
}

static unsigned get16le(const unsigned char *p) { return (unsigned)p[0] | ((unsigned)p[1] << 8); }

// ─────────────────── пул соединений к ДЦ (x6 + x4) ───────────────────
// Держим заранее открытые соединения к ДЦ, чтобы клиенту не ждать
// установку соединения: 6 штук по IPv6 и 4 по IPv4, с постоянным догревом.

typedef struct { int fd; int dc; int v6; } pool_conn;

static int connect_dc(int dc_idx, int prefer_v6);

static pool_conn g_pool[TG_POOL_X6 + TG_POOL_X4];
static volatile sig_atomic_t g_pool_stop = 0;

static int pool_target_v6(int i) { return i < TG_POOL_X6; }

static void pool_warm_one(int idx) {
    if (idx < 0 || idx >= TG_POOL_X6 + TG_POOL_X4) return;
    if (g_pool[idx].fd > 0) return;
    int want_v6 = pool_target_v6(idx);
    int fd = connect_dc((idx % 5) + 1, want_v6);
    if (fd < 0) return;
    g_pool[idx].fd = fd;
    g_pool[idx].dc = (idx % 5) + 1;
    g_pool[idx].v6 = want_v6;
}

static void pool_close_all(void) {
    for (int i = 0; i < TG_POOL_X6 + TG_POOL_X4; i++) {
        if (g_pool[i].fd > 0) { close(g_pool[i].fd); g_pool[i].fd = 0; }
    }
}

static int pool_take(int prefer_v6) {
    for (int i = 0; i < TG_POOL_X6 + TG_POOL_X4; i++) {
        if (g_pool[i].fd > 0 && g_pool[i].v6 == (prefer_v6 ? 1 : 0)) {
            int fd = g_pool[i].fd;
            g_pool[i].fd = 0;
            return fd;
        }
    }
    return -1;
}

static void *pool_thread(void *arg) {
    (void)arg;
    while (!g_pool_stop) {
        for (int i = 0; i < TG_POOL_X6 + TG_POOL_X4; i++)
            if (g_pool[i].fd <= 0) pool_warm_one(i);
        usleep(300000);
    }
    pool_close_all();
    return NULL;
}

// ─────────────────────────── ввод-вывод ───────────────────────────

static int read_full(int fd, unsigned char *b, int n, int timeout_s) {
    struct pollfd p = { fd, POLLIN, 0 };
    int got = 0;
    while (got < n) {
        int r = poll(&p, 1, timeout_s * 1000);
        if (r <= 0) return -1;
        ssize_t k = recv(fd, b + got, (size_t)(n - got), 0);
        if (k <= 0) return -1;
        got += (int)k;
    }
    return got;
}

static int write_full(int fd, const unsigned char *b, int n) {
    int sent = 0;
    while (sent < n) {
        ssize_t k = send(fd, b + sent, (size_t)(n - sent), MSG_NOSIGNAL);
        if (k <= 0) return -1;
        sent += (int)k;
    }
    return sent;
}


// ──────────────────────── fake-TLS (intermediate) ────────────────────────
// Клиент шлёт настоящий ClientHello, в который вписан HMAC-SHA256 от секрета.
// Прокси проверяет подпись и отвечает поддельным ServerHello: сертификат
// не выдаётся, вместо него идёт мусор длиной 1024..4096 байт.

#define TLS_REC_CHANGE  0x14
#define TLS_REC_APP     0x17
#define TLS_VERS        "\x03\x03"
#define TLS_VERS_LEN    3
#define TLS_DIGEST_LEN  32
#define TLS_DIGEST_POS  11
#define TLS_SESSLEN_POS (TLS_DIGEST_POS + TLS_DIGEST_LEN)
#define TLS_SESS_POS    (TLS_SESSLEN_POS + 1)

static int tls_write_record(int fd, const unsigned char *data, int n) {
    unsigned char hdr[5];
    hdr[0] = TLS_REC_APP;
    hdr[1] = 0x03; hdr[2] = 0x03;
    hdr[3] = (unsigned char)(n >> 8); hdr[4] = (unsigned char)n;
    unsigned char out[TG_BUFSIZE + 5];
    if (n > TG_BUFSIZE) return -1;
    memcpy(out, hdr, 5);
    memcpy(out + 5, data, (size_t)n);
    return write_full(fd, out, n + 5);
}

// читает очередную TLS-запись и возвращает полезную нагрузку
static int tls_read_record(int fd, unsigned char *out, int cap, int timeout_s) {
    unsigned char hdr[5];
    if (read_full(fd, hdr, 5, timeout_s) != 5) return -1;
    int type = hdr[0];
    if (type != TLS_REC_APP && type != TLS_REC_CHANGE) return -1;
    int len = (hdr[3] << 8) | hdr[4];
    if (len < 0 || len > cap) return -1;
    if (type == TLS_REC_CHANGE) {
        if (len) { unsigned char skip[512]; if (len > (int)sizeof(skip)) return -1;
                   if (read_full(fd, skip, len, timeout_s) != len) return -1; }
        return tls_read_record(fd, out, cap, timeout_s);
    }
    if (read_full(fd, out, len, timeout_s) != len) return -1;
    return len;
}

// x25519-публичный ключ вида «квадрат по модулю P» — как в эталоне
static int gen_x25519_like(void *out, size_t n) {
    unsigned char *o = out;
    BIGNUM *x = BN_new(), *p = BN_new();
    if (!x || !p) { if (x) BN_free(x); if (p) BN_free(p); return -1; }
    BN_CTX *ctx = BN_CTX_new();
    // P = 2^255 - 19
    BN_one(p);
    BN_lshift(p, p, 255);
    BN_sub_word(p, 19);
    BN_rand_range(x, p);
    BN_mod_mul(x, x, x, p, ctx);
    if (BN_bn2binpad(x, o, (int)n) < 0) { BN_free(x); BN_free(p); BN_CTX_free(ctx); return -1; }
    BN_free(x); BN_free(p); BN_CTX_free(ctx);
    return 0;
}

// Проверка ClientHello и ответ поддельным ServerHello.
// 1 — принято, 0 — отказ (клиент получит мусор, как и задумано протоколом).
static int fake_tls_handshake(int fd, const unsigned char *hs, int hs_len) {
    if (hs_len < TLS_SESS_POS + 2) return 0;
    int sess_len = hs[TLS_SESSLEN_POS];
    if (sess_len < 0 || TLS_SESS_POS + sess_len > hs_len) return 0;

    unsigned char msg[TG_BUFSIZE];
    int mlen = TLS_DIGEST_POS + TLS_DIGEST_LEN + (hs_len - TLS_DIGEST_POS - TLS_DIGEST_LEN);
    if (mlen > (int)sizeof(msg)) return 0;
    memcpy(msg, hs, (size_t)mlen);
    memset(msg + TLS_DIGEST_POS, 0, TLS_DIGEST_LEN);

    unsigned int mdlen = 0;
    unsigned char hmac[TLS_DIGEST_LEN];
    if (!HMAC(EVP_sha256(), g_secret, 16, msg, (size_t)mlen, hmac, &mdlen)) return 0;

    unsigned char xored[TLS_DIGEST_LEN];
    for (int i = 0; i < TLS_DIGEST_LEN; i++) xored[i] = (unsigned char)(hs[TLS_DIGEST_POS + i] ^ hmac[i]);
    int bad=0; for (int i = 0; i < TLS_DIGEST_LEN - 4; i++) if (xored[i] != 0) { bad=1; break; }
    if (bad) return 0;

    unsigned char ext[256];
    // 00 2e | 00 33 00 24 | 00 1d 00 20  -> далее ключ на 32 байта и 00 2b 00 02 03 04
    memcpy(ext, "\x00\x2e\x00\x33\x00\x24\x00\x1d\x00\x20", 10);
    if (gen_x25519_like(ext + 10, 32) != 0) return 0;
    memcpy(ext + 42, "\x00\x2b\x00\x02\x03\x04", 6);
    int ext_len = 48;

    unsigned char body[TG_BUFSIZE];
    int n = 0;
    body[n++] = 0x03; body[n++] = 0x03;                     // TLS_VERS
    memset(body + n, 0, TLS_DIGEST_LEN); n += TLS_DIGEST_LEN;
    body[n++] = (unsigned char)sess_len;
    memcpy(body + n, hs + TLS_SESS_POS, (size_t)sess_len); n += sess_len;
    body[n++] = 0x13; body[n++] = 0x01; body[n++] = 0x00;   // TLS_AES_128_GCM_SHA256 + null
    memcpy(body + n, ext, (size_t)ext_len); n += ext_len;

    unsigned char pkt[TG_BUFSIZE + 1024];
    int p = 0;
    pkt[p++] = 0x16; pkt[p++] = 0x03; pkt[p++] = 0x01;
    pkt[p++] = (unsigned char)(((n + 4) >> 8) & 0xFF);
    pkt[p++] = (unsigned char)((n + 4) & 0xFF);
    pkt[p++] = 0x02;
    pkt[p++] = (unsigned char)((n >> 16) & 0xFF);
    pkt[p++] = (unsigned char)((n >> 8) & 0xFF);
    pkt[p++] = (unsigned char)(n & 0xFF);
    memcpy(pkt + p, body, (size_t)n); p += n;

    // ChangeCipherSpec
    pkt[p++] = 0x14; pkt[p++] = 0x03; pkt[p++] = 0x03;
    pkt[p++] = 0x00; pkt[p++] = 0x01; pkt[p++] = 0x01;
    // «данные приложения» — правдоподобный HTTP/2 мусор
    pkt[p++] = 0x17; pkt[p++] = 0x03; pkt[p++] = 0x03;
    int http_len = 1024 + (rand() % 3072);
    pkt[p++] = (unsigned char)((http_len >> 8) & 0xFF);
    pkt[p++] = (unsigned char)(http_len & 0xFF);
    if (RAND_bytes(pkt + p, (size_t)http_len) != 1) return 0;
    p += http_len;

    // подписываем ответ тем же секретом
    unsigned int l2 = 0;
    unsigned char sign[TLS_DIGEST_LEN];
    if (!HMAC(EVP_sha256(), g_secret, 16, (const unsigned char *)hs + TLS_DIGEST_POS,
              TLS_DIGEST_LEN, sign, &l2)) return 0;
    unsigned char signed_buf[TLS_DIGEST_POS + TLS_DIGEST_LEN];
    memcpy(signed_buf, hs + TLS_DIGEST_POS, TLS_DIGEST_LEN);
    for (int i = 0; i < TLS_DIGEST_LEN; i++) signed_buf[i] ^= sign[i];

    if (l2 != TLS_DIGEST_LEN) return 0;
    unsigned char out[TLS_DIGEST_POS + TLS_DIGEST_LEN + 4096];
    if (p + 4 > (int)sizeof(out)) return 0;
    memcpy(out, pkt, TLS_DIGEST_POS);
    unsigned int h2len = 0;
    unsigned char h2[TLS_DIGEST_LEN];
    if (!HMAC(EVP_sha256(), g_secret, 16, signed_buf, TLS_DIGEST_LEN, h2, &h2len)) return 0;
    memcpy(out + TLS_DIGEST_POS, h2, TLS_DIGEST_LEN);
    memcpy(out + TLS_DIGEST_POS + TLS_DIGEST_LEN, pkt + TLS_DIGEST_POS + TLS_DIGEST_LEN,
           (size_t)(p - TLS_DIGEST_POS - TLS_DIGEST_LEN));

    if (write_full(fd, out, p) != p) return 0;
    return 1;
}

// ─────────────────── разбор 64-байтового кадра ───────────────────

typedef struct {
    tg_ctr dec;                 // клиент -> прокси
    tg_ctr enc;                 // прокси -> клиент
    tg_ctr dc_dec;              // ДЦ -> прокси
    tg_ctr dc_enc;              // прокси -> ДЦ
    int  proto;                 // 0 abridged, 1 intermediate, 2 secure
    int  dc_idx;                // 0..4
    int  fake_tls;
} tg_session;

static int parse_handshake(tg_session *s, const unsigned char hs[TG_HANDSHAKE_LEN]) {
    const unsigned char *pv = hs + TG_SKIP_LEN;           // prekey(32)+iv(16)
    unsigned char dec_key[32], enc_key[32];
    unsigned char reversed[TG_PREKEY_LEN + TG_IV_LEN];
    unsigned char dec[64], probe[64];

    derive_key(pv, dec_key);
    if (ctr_new(&s->dec, dec_key, pv + TG_PREKEY_LEN) != 0) return -1;
    int dn = ctr_apply(&s->dec, hs, dec, 64);
    if (dn != 64) { ctr_free(&s->dec); return -1; }

    if (memcmp(dec + TG_PROTO_TAG_POS, TAG_ABRIDGED, 4) == 0)      s->proto = 0;
    else if (memcmp(dec + TG_PROTO_TAG_POS, TAG_INTERMEDIATE, 4) == 0) s->proto = 1;
    else if (memcmp(dec + TG_PROTO_TAG_POS, TAG_SECURE, 4) == 0) s->proto = 2;
    else { ctr_free(&s->dec); return -2; }

    s->dc_idx = (int)(short)get16le(dec + TG_DCIDX_POS);
    s->fake_tls = (s->proto == 2);
    fprintf(stderr, "[telegram] handshake принят: proto=%s dc=%d\n",
            s->proto == 0 ? "abridged" : (s->proto == 2 ? "secure" : "intermediate"),
            s->dc_idx);

    // симметричная ветка: тот же prekey+iv, но перевёрнутый
    for (int i = 0; i < TG_PREKEY_LEN + TG_IV_LEN; i++)
        reversed[i] = pv[TG_PREKEY_LEN + TG_IV_LEN - 1 - i];
    derive_key(reversed, enc_key);
    if (ctr_new(&s->enc, enc_key, reversed + TG_PREKEY_LEN) != 0) { ctr_free(&s->dec); return -1; }
    (void)probe;
    return 0;
}

// ────────────────────── подключение к ДЦ Telegram ──────────────────────

static int connect_dc(int dc_idx, int prefer_v6) {
    int idx = dc_idx < 0 ? -dc_idx - 1 : dc_idx - 1;
    if (idx < 0 || idx > 4) return -1;

    for (int pass = 0; pass < 2; pass++) {
        int use_v6 = prefer_v6 ? (pass == 0) : (pass == 1);
        const char *host = use_v6 ? DC_V6[idx] : DC_V4[idx];
        int fd = socket(use_v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        struct timeval tv = { 10, 0 };
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        {
            char port[8];
            snprintf(port, sizeof(port), "%d", TG_DC_PORT);
            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = use_v6 ? AF_INET6 : AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(host, port, &hints, &res) != 0 || !res) continue;
            fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (fd < 0) { freeaddrinfo(res); continue; }
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            int ok = connect(fd, res->ai_addr, res->ai_addrlen) == 0;
            freeaddrinfo(res);
            if (ok) return fd;
            close(fd);
        }
    }
    return -1;
}

// кадр, который прокси шлёт ДЦ в начале соединения
static int dc_handshake(int dfd, tg_session *s, const unsigned char client_pv[TG_PREKEY_LEN + TG_IV_LEN]) {
    unsigned char rnd[TG_HANDSHAKE_LEN];
    if (RAND_bytes(rnd, sizeof(rnd)) != 1) return -1;

    const unsigned char *tag = s->proto == 0 ? TAG_ABRIDGED
                           : (s->proto == 2 ? TAG_SECURE : TAG_INTERMEDIATE);
    memcpy(rnd + TG_PROTO_TAG_POS, tag, 4);

    // эталон: в кадр для ДЦ кладём перевёрнутые prekey+iv клиента
    for (int i = 0; i < TG_PREKEY_LEN + TG_IV_LEN; i++)
        rnd[TG_SKIP_LEN + i] = client_pv[TG_PREKEY_LEN + TG_IV_LEN - 1 - i];

    // из rnd[8..56] получаем два шифра ноги ДЦ
    unsigned char rev[TG_PREKEY_LEN + TG_IV_LEN], k1[32], k2[32];
    for (int i = 0; i < TG_PREKEY_LEN + TG_IV_LEN; i++)
        rev[i] = rnd[TG_SKIP_LEN + TG_PREKEY_LEN + TG_IV_LEN - 1 - i];
    derive_key(rev, k1);          // расшифровка того, что шлёт ДЦ
    derive_key(rnd + TG_SKIP_LEN, k2);  // шифрование того, что шлём ДЦ
    if (ctr_new(&s->dc_dec, k1, rev + TG_PREKEY_LEN) != 0) return -1;
    if (ctr_new(&s->dc_enc, k2, rnd + TG_SKIP_LEN + TG_PREKEY_LEN) != 0) {
        ctr_free(&s->dc_dec); return -1;
    }

    // в эталоне шифруется только хвост 56..64
    unsigned char wire[TG_HANDSHAKE_LEN];
    memcpy(wire, rnd, TG_PROTO_TAG_POS);
    if (ctr_apply(&s->dc_enc, rnd + TG_PROTO_TAG_POS, wire + TG_PROTO_TAG_POS,
                  TG_HANDSHAKE_LEN - TG_PROTO_TAG_POS) != TG_HANDSHAKE_LEN - TG_PROTO_TAG_POS)
        return -1;
    return write_full(dfd, wire, sizeof(wire));
}

// ─────────────────────── релей клиент <-> ДЦ ───────────────────────

static int relay(int cfd, int dfd, tg_session *s) {
    if (s->fake_tls) {
        unsigned char cbuf[TG_BUFSIZE], dbuf[TG_BUFSIZE];
        struct pollfd p[2] = { { cfd, POLLIN, 0 }, { dfd, POLLIN, 0 } };
        for (;;) {
            int r = poll(p, 2, TG_READ_TMO * 1000);
            if (r <= 0) return -1;
            for (int i = 0; i < 2; i++) {
                if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
                unsigned char *buf = (i == 0) ? cbuf : dbuf;
                ssize_t n = (i == 0) ? tls_read_record(cfd, buf, TG_BUFSIZE, TG_READ_TMO)
                                     : recv(dfd, buf, sizeof(buf), 0);
                if (n <= 0) return -1;
                unsigned char mid[TG_BUFSIZE], out[TG_BUFSIZE];
                if (i == 0) {
                    int m = ctr_apply(&s->dec, buf, mid, (int)n);
                    if (m < 0) return -1;
                    m = ctr_apply(&s->dc_enc, mid, out, m);
                    if (m < 0) return -1;
                    if (write_full(dfd, out, m) != m) return -1;
                } else {
                    int m = ctr_apply(&s->dc_dec, buf, mid, (int)n);
                    if (m < 0) return -1;
                    m = ctr_apply(&s->enc, mid, out, m);
                    if (m < 0) return -1;
                    if (tls_write_record(cfd, out, m) != m + 5) return -1;
                }
            }
        }
    }
    unsigned char cbuf[TG_BUFSIZE], dbuf[TG_BUFSIZE];
    struct pollfd p[2] = {
        { .fd = cfd, .events = POLLIN },
        { .fd = dfd, .events = POLLIN },
    };
    for (;;) {
        int r = poll(p, 2, TG_READ_TMO * 1000);
        if (r <= 0) return -1;
        for (int i = 0; i < 2; i++) {
            if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            unsigned char *buf = (i == 0) ? cbuf : dbuf;
            ssize_t n = recv(p[i].fd, buf, sizeof(cbuf), 0);
            if (n <= 0) return -1;
            unsigned char mid[TG_BUFSIZE], out[TG_BUFSIZE];
            if (i == 0) {
                int m = ctr_apply(&s->dec, buf, mid, (int)n);          // снимаем обфускацию клиента
                if (m < 0) return -1;
                m = ctr_apply(&s->dc_enc, mid, out, m);                // надеваем обфускацию ДЦ
                if (m < 0) return -1;
                if (write_full(dfd, out, m) != m) return -1;
            } else {
                int m = ctr_apply(&s->dc_dec, buf, mid, (int)n);
                if (m < 0) return -1;
                m = ctr_apply(&s->enc, mid, out, m);
                if (m < 0) return -1;
                if (write_full(cfd, out, m) != m) return -1;
            }
        }
    }
}

// ───────────────────────── обработка клиента ─────────────────────────

static void handle_client(int cfd, const struct sockaddr_storage *peer) {
    tg_session s;
    memset(&s, 0, sizeof(s));
    s.dec.ctx = NULL; s.enc.ctx = NULL;

    (void)peer;
    struct timeval tv = { TG_HANDSHAKE_TMO, 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char hs[TG_HANDSHAKE_LEN];
    int use_tls = 0;

    // признак fake-TLS: первые байты 0x16 0x03 0x01 и длина хендшейка >= 512
    if (read_full(cfd, hs, 3, TG_HANDSHAKE_TMO) != 3) return;
    if (hs[0] == 0x16 && hs[1] == 0x03 && hs[2] == 0x01) {
        if (read_full(cfd, hs + 3, 2, TG_HANDSHAKE_TMO) != 2) return;
        int tls_len = (hs[3] << 8) | hs[4];
        if (tls_len >= 512 && tls_len < 8192) {
            // +5: заголовок записи кладём в тот же буфер, иначе переполнение
            unsigned char *th = malloc((size_t)tls_len + 5);
            if (!th) return;
            memcpy(th, hs, 5);
            if (read_full(cfd, th + 5, tls_len, TG_HANDSHAKE_TMO) != tls_len) { free(th); return; }
            if (!fake_tls_handshake(cfd, th, tls_len)) { free(th); return; }
            free(th);
            use_tls = 1;
            // дальше 64-байтовый кадр идёт внутри TLS-записей приложения
            int n = 0;
            while (n < TG_HANDSHAKE_LEN) {
                int got = tls_read_record(cfd, hs + n, TG_HANDSHAKE_LEN - n, TG_HANDSHAKE_TMO);
                if (got < 0) return;
                n += got;
            }
        } else {
            if (read_full(cfd, hs + 5, TG_HANDSHAKE_LEN - 5, TG_HANDSHAKE_TMO) != TG_HANDSHAKE_LEN - 5) return;
        }
    } else {
        if (read_full(cfd, hs + 3, TG_HANDSHAKE_LEN - 3, TG_HANDSHAKE_TMO) != TG_HANDSHAKE_LEN - 3) return;
    }

    if (parse_handshake(&s, hs) != 0) return;
    unsigned char client_pv[TG_PREKEY_LEN + TG_IV_LEN];
    memcpy(client_pv, hs + TG_SKIP_LEN, sizeof(client_pv));
    s.fake_tls = use_tls;

    int dfd = pool_take(telegram_get_ctx()->prefer_ipv6);
    if (dfd < 0) dfd = connect_dc(s.dc_idx, telegram_get_ctx()->prefer_ipv6);
    if (dfd < 0) { ctr_free(&s.dec); ctr_free(&s.enc); return; }

    if (dc_handshake(dfd, &s, client_pv) != 0) { close(dfd); ctr_free(&s.dec); ctr_free(&s.enc); return; }

    struct timeval tv2 = { 0, 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    setsockopt(dfd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));

    relay(cfd, dfd, &s);

    close(dfd);
    ctr_free(&s.dec);
    ctr_free(&s.enc);
}

// ─────────────────────────── accept-цикл ───────────────────────────

static volatile sig_atomic_t g_running = 0;
static int g_listen_fd = -1;

static void on_term(int sig) { (void)sig; g_running = 0; if (g_listen_fd >= 0) { close(g_listen_fd); g_listen_fd = -1; } }

static void proxy_child(int port) {
    setsid();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, on_term);

    secret_init();

    int one = 1;
    int lfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (lfd < 0) { int v4 = socket(AF_INET, SOCK_STREAM, 0); if (v4 < 0) _exit(1); lfd = v4; }
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* dual-stack: клиент может прийти и по IPv4, и по IPv6 */
    int off = 0;
    if (lfd != -1) setsockopt(lfd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

    struct sockaddr_in6 a;
    memset(&a, 0, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_port = htons((uint16_t)port);
    a.sin6_addr = in6addr_any;
    if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        struct sockaddr_in b;
        memset(&b, 0, sizeof(b));
        b.sin_family = AF_INET;
        b.sin_port = htons((uint16_t)port);
        b.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(lfd, (struct sockaddr *)&b, sizeof(b)) != 0) _exit(2);
    }
    if (listen(lfd, 128) != 0) _exit(3);

    g_listen_fd = lfd;
    g_running = 1;
    pthread_t pool_thr;
    if (pthread_create(&pool_thr, NULL, pool_thread, NULL) == 0) {
        pthread_detach(pool_thr);
        fprintf(stderr, "[telegram] пул соединений: x6=%d x4=%d\n", TG_POOL_X6, TG_POOL_X4);
    }
    fprintf(stderr, "[telegram] MTProxy :%d готов (пул x6=%d x4=%d)\n", port, TG_POOL_X6, TG_POOL_X4);
    fflush(stderr);

    while (g_running) {
        struct sockaddr_storage peer;
        socklen_t plen = sizeof(peer);
        int c = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (c < 0) { if (errno == EINTR) continue; break; }
        pid_t p = fork();
        if (p == 0) {
            close(lfd);
            int n1 = 1;
            setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &n1, sizeof(n1));
            handle_client(c, &peer);
            close(c);
            _exit(0);
        }
        if (p > 0) {
            // держим размер пула: не более TG_POOL_X6+x4 одновременных детей
            int cur = 0;
            for (int i = 0; i < TG_POOL_X6 + TG_POOL_X4; i++) {
                if (waitpid(-1, NULL, WNOHANG) > 0) cur--;
            }
            (void)cur;
        }
        close(c);
    }
    _exit(0);
}

int telegram_proxy_start(int port) {
    if (telegram_proxy_running()) return 0;
    if (port <= 0) port = TG_PROXY_PORT;
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) { proxy_child(port); _exit(0); }
    telegram_get_ctx()->relay_pid = (int)p;
    telegram_get_ctx()->relay_running = 1;
    return 0;
}

void telegram_proxy_stop(void) {
    int pid = telegram_get_ctx()->relay_pid;
    if (pid > 0) {
        kill(pid, SIGTERM);
        int st;
        for (int i = 0; i < 20; i++) {
            if (waitpid(pid, &st, WNOHANG) == pid) break;
            usleep(50000);
        }
        waitpid(pid, &st, WNOHANG);
    }
    telegram_get_ctx()->relay_pid = -1;
    telegram_get_ctx()->relay_running = 0;
}

int telegram_proxy_running(void) {
    int pid = telegram_get_ctx()->relay_pid;
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    telegram_get_ctx()->relay_pid = -1;
    telegram_get_ctx()->relay_running = 0;
    return 0;
}
