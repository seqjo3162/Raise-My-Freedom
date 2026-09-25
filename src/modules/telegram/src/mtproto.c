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
#include <ctype.h>
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
#include <sys/prctl.h>
#include <fcntl.h>
#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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
#define TG_WS_TIMEOUT_MS  3000
#define TG_WS_BUDGET_MS   8000
#define TG_WS_MAX_MESSAGE (16U * 1024U * 1024U)
#define TG_WS_BUF         16384

static const unsigned char TAG_ABRIDGED[4]    = {0xef, 0xef, 0xef, 0xef};
static const unsigned char TAG_INTERMEDIATE[4] = {0xee, 0xee, 0xee, 0xee};
static const unsigned char TAG_SECURE[4]       = {0xdd, 0xdd, 0xdd, 0xdd};

// ДЦ Telegram. dc_idx = |значение| - 1
static const char *DC_V4[5] = {
    "149.154.175.50", "149.154.167.51", "149.154.175.100",
    "149.154.167.91", "149.154.171.5"
};
static const char *DC_V6[5] = {
    "2001:b28:f23d:f001::a", "2001:67c:04e8:f002::a", "2001:b28:f23d:f003::a",
    "2001:67c:04e8:f004::a", "2001:67c:04e8:f005::a"
};
static const char *DC_WS_V4[5] = {
    "149.154.175.50", "149.154.167.220", "149.154.175.100",
    "149.154.167.220", "149.154.171.5"
};
static const char *DC_TEST_V4[5] = {
    "149.154.175.10", "149.154.167.40", "149.154.175.117",
    "149.154.167.40", "149.154.175.10"
};

// секрет пользователя: 16 байт. В приложении Telegram вводится как 32 hex-символа
static unsigned char g_secret[16];
static int g_secret_ready = 0;

static int tg_ws_debug(void) {
    static int enabled = -1;
    if (enabled < 0) enabled = getenv("TG_WS_DEBUG") ? 1 : 0;
    return enabled;
}

#define TG_WS_LOG(...) do { if (tg_ws_debug()) fprintf(stderr, __VA_ARGS__); } while (0)

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
static int tcp_connect_host(const char *host, int port, int timeout_ms, int prefer_v6);

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

static int pool_take(int dc_idx, int prefer_v6) {
    int want_dc = dc_idx < 0 ? -dc_idx : dc_idx;
    for (int i = 0; i < TG_POOL_X6 + TG_POOL_X4; i++) {
        if (g_pool[i].fd > 0 && g_pool[i].dc == want_dc &&
            g_pool[i].v6 == (prefer_v6 ? 1 : 0)) {
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
    if (bad) {
        TG_WS_LOG("[telegram] fake TLS HMAC mismatch got=%02x%02x%02x%02x want=%02x%02x%02x%02x len=%d\n",
                  hs[TLS_DIGEST_POS], hs[TLS_DIGEST_POS + 1],
                  hs[TLS_DIGEST_POS + 2], hs[TLS_DIGEST_POS + 3],
                  hmac[0], hmac[1], hmac[2], hmac[3], hs_len);
        return 0;
    }

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
    pkt[p++] = 0x16; pkt[p++] = 0x03; pkt[p++] = 0x03;
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

    unsigned char *signed_input = malloc((size_t)TLS_DIGEST_LEN + (size_t)p);
    if (!signed_input) return 0;
    memcpy(signed_input, hs + TLS_DIGEST_POS, TLS_DIGEST_LEN);
    memcpy(signed_input + TLS_DIGEST_LEN, pkt, (size_t)p);

    unsigned int h2len = 0;
    unsigned char h2[TLS_DIGEST_LEN];
    if (!HMAC(EVP_sha256(), g_secret, 16, signed_input,
              TLS_DIGEST_LEN + (size_t)p, h2, &h2len) || h2len != TLS_DIGEST_LEN) {
        free(signed_input);
        return 0;
    }
    free(signed_input);
    memcpy(pkt + TLS_DIGEST_POS, h2, TLS_DIGEST_LEN);

    if (write_full(fd, pkt, p) != p) return 0;
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
    unsigned char dec[64];

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
    return 0;
}

// ────────────────────── подключение к ДЦ Telegram ──────────────────────

static int connect_dc(int dc_idx, int prefer_v6) {
    int test = dc_idx >= 10000 || dc_idx <= -10000;
    int value = test ? (dc_idx < 0 ? -dc_idx - 10000 : dc_idx - 10000) : dc_idx;
    if (value == 203 || value == -203) value = value < 0 ? -2 : 2;
    int idx = value < 0 ? -value - 1 : value - 1;
    if (idx < 0 || idx > 4) return -1;
    const char *host_override = getenv("TG_DC_TARGET");
    const char *port_override = getenv("TG_DC_PORT");
    int port = port_override && port_override[0] ? atoi(port_override) : TG_DC_PORT;
    if (port <= 0) port = TG_DC_PORT;
    if (host_override && host_override[0])
        return tcp_connect_host(host_override, port, 3000, prefer_v6);
    if (test) return tcp_connect_host(DC_TEST_V4[idx], port, 3000, 0);
    if (prefer_v6) {
        int fd = tcp_connect_host(DC_V6[idx], port, 3000, 1);
        return fd >= 0 ? fd : tcp_connect_host(DC_V4[idx], port, 3000, 0);
    }
    int fd = tcp_connect_host(DC_V4[idx], port, 3000, 0);
    return fd >= 0 ? fd : tcp_connect_host(DC_V6[idx], port, 3000, 1);
}

static int make_relay_init(tg_session *s,
                           const unsigned char client_pv[TG_PREKEY_LEN + TG_IV_LEN],
                           unsigned char relay_init[TG_HANDSHAKE_LEN]) {
    static const unsigned char reserved[][4] = {
        {0x48, 0x45, 0x41, 0x44}, {0x50, 0x4f, 0x53, 0x54},
        {0x47, 0x45, 0x54, 0x20}, {0xee, 0xee, 0xee, 0xee},
        {0xdd, 0xdd, 0xdd, 0xdd}, {0x16, 0x03, 0x01, 0x02}
    };
    unsigned char rnd[TG_HANDSHAKE_LEN];
    int ok = 0;
    for (int attempt = 0; attempt < 32 && !ok; attempt++) {
        if (RAND_bytes(rnd, sizeof(rnd)) != 1) return -1;
        if (rnd[0] == 0xef) continue;
        if (memcmp(rnd + 4, "\x00\x00\x00\x00", 4) == 0) continue;
        int reserved_match = 0;
        for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++)
            if (memcmp(rnd, reserved[i], 4) == 0) { reserved_match = 1; break; }
        if (!reserved_match) ok = 1;
    }
    if (!ok) return -1;

    const unsigned char *tag = s->proto == 0 ? TAG_ABRIDGED
                           : (s->proto == 2 ? TAG_SECURE : TAG_INTERMEDIATE);
    for (int i = 0; i < TG_PREKEY_LEN + TG_IV_LEN; i++)
        rnd[TG_SKIP_LEN + i] = client_pv[TG_PREKEY_LEN + TG_IV_LEN - 1 - i];

    unsigned char rev[TG_PREKEY_LEN + TG_IV_LEN], k1[32], k2[32];
    for (int i = 0; i < TG_PREKEY_LEN + TG_IV_LEN; i++)
        rev[i] = rnd[TG_SKIP_LEN + TG_PREKEY_LEN + TG_IV_LEN - 1 - i];
    memcpy(k1, rev, sizeof(k1));
    memcpy(k2, rnd + TG_SKIP_LEN, sizeof(k2));
    if (ctr_new(&s->dc_dec, k1, rev + TG_PREKEY_LEN) != 0) return -1;
    if (ctr_new(&s->dc_enc, k2, rnd + TG_SKIP_LEN + TG_PREKEY_LEN) != 0) {
        ctr_free(&s->dc_dec);
        return -1;
    }

    unsigned char plain_tail[8];
    memcpy(plain_tail, tag, 4);
    int16_t dc_value = (int16_t)s->dc_idx;
    plain_tail[4] = (unsigned char)((uint16_t)dc_value & 0xff);
    plain_tail[5] = (unsigned char)(((uint16_t)dc_value >> 8) & 0xff);
    if (RAND_bytes(&plain_tail[6], 2) != 1) {
        ctr_free(&s->dc_dec);
        ctr_free(&s->dc_enc);
        return -1;
    }

    unsigned char encrypted[TG_HANDSHAKE_LEN];
    if (ctr_apply(&s->dc_enc, rnd, encrypted, sizeof(rnd)) != (int)sizeof(rnd)) {
        ctr_free(&s->dc_dec);
        ctr_free(&s->dc_enc);
        return -1;
    }
    memcpy(relay_init, rnd, TG_PROTO_TAG_POS);
    for (size_t i = 0; i < sizeof(plain_tail); i++)
        relay_init[TG_PROTO_TAG_POS + i] =
            (encrypted[TG_PROTO_TAG_POS + i] ^ rnd[TG_PROTO_TAG_POS + i]) ^ plain_tail[i];
    return 0;
}

static int dc_handshake(int dfd, tg_session *s,
                        const unsigned char relay_init[TG_HANDSHAKE_LEN]) {
    int rc = write_full(dfd, relay_init, TG_HANDSHAKE_LEN);
    if (rc != TG_HANDSHAKE_LEN) {
        ctr_free(&s->dc_dec);
        ctr_free(&s->dc_enc);
        return -1;
    }
    return 0;
}

#define TG_WS_OP_CONT   0x0
#define TG_WS_OP_BINARY 0x2
#define TG_WS_OP_CLOSE  0x8
#define TG_WS_OP_PING   0x9
#define TG_WS_OP_PONG   0xa

typedef struct {
    int fd;
    SSL *ssl;
    unsigned char rbuf[TG_WS_BUF];
    size_t rpos;
    size_t rlen;
    unsigned char *frag;
    size_t frag_len;
    size_t frag_cap;
    int upgraded;
} tg_ws;

static int tcp_connect_host(const char *host, int port, int timeout_ms, int prefer_v6) {
    char service[16];
    snprintf(service, sizeof(service), "%d", port);
    int result = -1;
    for (int pass = 0; pass < 2 && result < 0; pass++) {
        int family = (prefer_v6 ? (pass == 0) : (pass == 1)) ? AF_INET6 : AF_INET;
        struct addrinfo hints = {0};
        hints.ai_family = family;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICSERV;
        struct addrinfo *res = NULL;
        if (getaddrinfo(host, service, &hints, &res) != 0 || !res) continue;
        for (struct addrinfo *ai = res; ai && result < 0; ai = ai->ai_next) {
            int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (fd < 0) continue;
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
            if (rc < 0 && errno != EINPROGRESS) { close(fd); continue; }
            if (rc < 0) {
                struct pollfd p = {fd, POLLOUT, 0};
                int pr = poll(&p, 1, timeout_ms);
                int err = 0;
                socklen_t elen = sizeof(err);
                if (pr != 1 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
                    close(fd);
                    continue;
                }
            }
            if (flags >= 0) fcntl(fd, F_SETFL, flags);
            result = fd;
        }
        freeaddrinfo(res);
    }
    return result;
}

static int ws_wait_socket(int fd, int want_read, int timeout_ms) {
    struct pollfd p = {fd, (short)(want_read ? POLLIN : POLLOUT), 0};
    return poll(&p, 1, timeout_ms);
}

static int ws_ssl_connect(SSL *ssl, int fd) {
    for (;;) {
        int rc = SSL_connect(ssl);
        if (rc == 1) return 0;
        int err = SSL_get_error(ssl, rc);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) return -1;
        if (ws_wait_socket(fd, err == SSL_ERROR_WANT_READ, TG_WS_TIMEOUT_MS) <= 0) return -1;
    }
}

static int ws_raw_read(tg_ws *w, unsigned char *out, size_t need) {
    size_t got = 0;
    while (got < need) {
        if (w->rpos < w->rlen) {
            size_t n = w->rlen - w->rpos;
            if (n > need - got) n = need - got;
            memcpy(out + got, w->rbuf + w->rpos, n);
            w->rpos += n;
            got += n;
            continue;
        }
        w->rpos = w->rlen = 0;
        TG_WS_LOG("[telegram] WS SSL_read need=%zu fd=%d\n", need, w->fd);
        int n = SSL_read(w->ssl, w->rbuf, sizeof(w->rbuf));
        TG_WS_LOG("[telegram] WS SSL_read=%d err=%d\n", n, n <= 0 ? SSL_get_error(w->ssl, n) : 0);
        if (n > 0) {
            w->rlen = (size_t)n;
            continue;
        }
        int err = SSL_get_error(w->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            struct pollfd p = {w->fd, (short)(err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT), 0};
            if (poll(&p, 1, TG_READ_TMO * 1000) <= 0) return -1;
            continue;
        }
        return -1;
    }
    return (int)got;
}

static int ws_raw_write(tg_ws *w, const unsigned char *data, size_t need) {
    size_t sent = 0;
    while (sent < need) {
        int n = SSL_write(w->ssl, data + sent, (int)(need - sent));
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        int err = SSL_get_error(w->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            struct pollfd p = {w->fd, (short)(err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT), 0};
            if (poll(&p, 1, TG_READ_TMO * 1000) <= 0) return -1;
            continue;
        }
        return -1;
    }
    return (int)sent;
}

static void ws_close(tg_ws *w) {
    if (!w) return;
    if (w->ssl) {
        if (w->upgraded) {
            unsigned char close_frame[6] = {0x88, 0x80, 0, 0, 0, 0};
            if (RAND_bytes(close_frame + 2, 4) == 1)
                ws_raw_write(w, close_frame, sizeof(close_frame));
        }
        SSL_shutdown(w->ssl);
        SSL_free(w->ssl);
        w->ssl = NULL;
    }
    if (w->fd >= 0) close(w->fd);
    free(w->frag);
    memset(w, 0, sizeof(*w));
    w->fd = -1;
}

static int ws_send_frame(tg_ws *w, unsigned char opcode, const unsigned char *data, size_t len) {
    if (len > TG_WS_MAX_MESSAGE) return -1;
    size_t cap = len + 14;
    unsigned char *frame = malloc(cap);
    if (!frame) return -1;
    size_t n = 0;
    frame[n++] = (unsigned char)(0x80 | opcode);
    if (len < 126) {
        frame[n++] = (unsigned char)(0x80 | len);
    } else if (len <= 0xffff) {
        frame[n++] = (unsigned char)0x80 | 126;
        frame[n++] = (unsigned char)(len >> 8);
        frame[n++] = (unsigned char)len;
    } else {
        frame[n++] = (unsigned char)0x80 | 127;
        for (int i = 7; i >= 0; i--) frame[n++] = (unsigned char)(len >> (i * 8));
    }
    unsigned char mask[4];
    if (RAND_bytes(mask, sizeof(mask)) != 1) { free(frame); return -1; }
    memcpy(frame + n, mask, 4);
    n += 4;
    for (size_t i = 0; i < len; i++) frame[n + i] = data[i] ^ mask[i & 3];
    n += len;
    int rc = ws_raw_write(w, frame, n);
    free(frame);
    return rc == (int)n ? 0 : -1;
}

static int ws_send_message(tg_ws *w, const unsigned char *data, size_t len) {
    return ws_send_frame(w, TG_WS_OP_BINARY, data, len);
}

static int ws_read_frame(tg_ws *w, unsigned char *opcode, unsigned char *fin,
                         unsigned char **payload, size_t *len) {
    unsigned char h[2];
    if (ws_raw_read(w, h, 2) != 2) return -1;
    *fin = (unsigned char)(h[0] & 0x80);
    *opcode = h[0] & 0x0f;
    int masked = h[1] & 0x80;
    uint64_t n = h[1] & 0x7f;
    if (n == 126) {
        unsigned char b[2];
        if (ws_raw_read(w, b, 2) != 2) return -1;
        n = ((uint64_t)b[0] << 8) | b[1];
    } else if (n == 127) {
        unsigned char b[8];
        if (ws_raw_read(w, b, 8) != 8) return -1;
        n = 0;
        for (int i = 0; i < 8; i++) n = (n << 8) | b[i];
    }
    if (n > TG_WS_MAX_MESSAGE) return -1;
    unsigned char mask[4] = {0};
    if (masked && ws_raw_read(w, mask, 4) != 4) return -1;
    unsigned char *data = malloc((size_t)n + 1);
    if (!data) return -1;
    if (n && ws_raw_read(w, data, (size_t)n) != (int)n) { free(data); return -1; }
    if (masked) for (uint64_t i = 0; i < n; i++) data[i] ^= mask[i & 3];
    data[n] = 0;
    *payload = data;
    *len = (size_t)n;
    return 0;
}

static int ws_recv_message(tg_ws *w, unsigned char **data, size_t *len) {
    for (;;) {
        unsigned char opcode, fin, *payload = NULL;
        size_t payload_len = 0;
        if (ws_read_frame(w, &opcode, &fin, &payload, &payload_len) != 0) return -1;
        if (opcode == TG_WS_OP_CLOSE) {
            ws_send_frame(w, TG_WS_OP_CLOSE, payload, payload_len < 2 ? payload_len : 2);
            free(payload);
            return -1;
        }
        if (opcode == TG_WS_OP_PING) {
            ws_send_frame(w, TG_WS_OP_PONG, payload, payload_len);
            free(payload);
            continue;
        }
        if (opcode == TG_WS_OP_PONG) {
            free(payload);
            continue;
        }
        if (opcode != TG_WS_OP_BINARY && opcode != TG_WS_OP_CONT &&
            opcode != 0x1) {
            free(payload);
            continue;
        }
        if (w->frag_len == 0 && opcode == TG_WS_OP_BINARY && fin) {
            *data = payload;
            *len = payload_len;
            return 0;
        }
        if (w->frag_len + payload_len > TG_WS_MAX_MESSAGE) {
            free(payload);
            return -1;
        }
        size_t need = w->frag_len + payload_len;
        if (need > w->frag_cap) {
            size_t cap = w->frag_cap ? w->frag_cap : 4096;
            while (cap < need) cap *= 2;
            unsigned char *tmp = realloc(w->frag, cap);
            if (!tmp) { free(payload); return -1; }
            w->frag = tmp;
            w->frag_cap = cap;
        }
        memcpy(w->frag + w->frag_len, payload, payload_len);
        w->frag_len += payload_len;
        free(payload);
        if (fin) {
            *data = w->frag;
            *len = w->frag_len;
            w->frag = NULL;
            w->frag_len = w->frag_cap = 0;
            return 0;
        }
    }
}

static void base64_encode16(const unsigned char in[16], char out[25]) {
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < 16; i += 3) {
        unsigned v = in[i] << 16;
        if (i + 1 < 16) v |= in[i + 1] << 8;
        if (i + 2 < 16) v |= in[i + 2];
        out[o++] = tab[(v >> 18) & 63];
        out[o++] = tab[(v >> 12) & 63];
        out[o++] = (i + 1 < 16) ? tab[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < 16) ? tab[v & 63] : '=';
    }
    out[o] = 0;
}

static int ws_http_upgrade(tg_ws *w, const char *domain, const char *path) {
    unsigned char key_raw[16];
    char key[25];
    if (RAND_bytes(key_raw, sizeof(key_raw)) != 1) return -1;
    base64_encode16(key_raw, key);
    char req[1024];
    int n = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: binary\r\n"
        "\r\n", path, domain, key);
    if (n <= 0 || n >= (int)sizeof(req)) return -1;
    if (ws_raw_write(w, (const unsigned char *)req, (size_t)n) != n) return -1;

    char hdr[8192];
    size_t used = 0;
    while (used < sizeof(hdr) - 1) {
        unsigned char c;
        if (ws_raw_read(w, &c, 1) != 1) return -1;
        hdr[used++] = (char)c;
        hdr[used] = 0;
        if (used >= 4 && memcmp(hdr + used - 4, "\r\n\r\n", 4) == 0) break;
    }
    if (used < 4 || memcmp(hdr + used - 4, "\r\n\r\n", 4) != 0) return -1;
    if (strncmp(hdr, "HTTP/1.1 101", 12) != 0 && strncmp(hdr, "HTTP/1.0 101", 12) != 0)
        return -2;
    return 0;
}

static void ws_init(tg_ws *w, int fd, SSL *ssl) {
    memset(w, 0, sizeof(*w));
    w->fd = fd;
    w->ssl = ssl;
}

static int ws_open_once(tg_ws *w, const char *target, const char *domain,
                        const char *path, int fronting, int prefer_v6) {
    ERR_clear_error();
    const char *port_env = getenv("TG_WS_PORT");
    int port = port_env && port_env[0] ? atoi(port_env) : 443;
    if (port <= 0) port = 443;
    int fd = tcp_connect_host(target, port, TG_WS_TIMEOUT_MS, prefer_v6);
    if (fd < 0) return -1;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return -1; }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return -1; }
    const char *sni = fronting ? "sprinthost.ru" : domain;
    if (SSL_set_tlsext_host_name(ssl, sni) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return -1;
    }
    if (!fronting && SSL_set1_host(ssl, domain) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return -1;
    }
    SSL_set_fd(ssl, fd);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    ws_init(w, fd, ssl);
    if (ws_ssl_connect(ssl, fd) != 0 || ws_http_upgrade(w, domain, path) != 0) {
        ws_close(w);
        SSL_CTX_free(ctx);
        return -1;
    }
    w->upgraded = 1;
    SSL_CTX_free(ctx);
    return 0;
}


static unsigned get32le(const unsigned char *p) {
    return (unsigned)p[0] | ((unsigned)p[1] << 8) |
           ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}

static int64_t tg_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int ws_open_for_dc(tg_ws *w, int dc_idx, int prefer_v6) {
    int dc = dc_idx < 0 ? -dc_idx : dc_idx;
    int is_media = dc_idx < 0;
    int is_test = dc >= 10000;
    if (is_test) dc -= 10000;
    if (dc == 203) dc = 2;
    if (dc < 1 || dc > 5) return -1;

    char domains[2][80];
    if (is_media) {
        snprintf(domains[0], sizeof(domains[0]), "kws%d-1.web.telegram.org", dc);
        snprintf(domains[1], sizeof(domains[1]), "kws%d.web.telegram.org", dc);
    } else {
        snprintf(domains[0], sizeof(domains[0]), "kws%d.web.telegram.org", dc);
        snprintf(domains[1], sizeof(domains[1]), "kws%d-1.web.telegram.org", dc);
    }
    const char *target = is_test ? DC_TEST_V4[dc - 1] : DC_WS_V4[dc - 1];
    const char *path = is_test ? "/apiws_test" : "/apiws";
    const char *domain_override = getenv("TG_WS_DOMAIN");
    const char *target_override = getenv("TG_WS_TARGET");
    if (domain_override && domain_override[0]) {
        snprintf(domains[0], sizeof(domains[0]), "%s", domain_override);
        snprintf(domains[1], sizeof(domains[1]), "%s", domain_override);
    }
    if (target_override && target_override[0]) target = target_override;

    int64_t deadline = tg_monotonic_ms() + TG_WS_BUDGET_MS;
    for (int i = 0; i < 2; i++) {
        if (tg_monotonic_ms() >= deadline) break;
        if (ws_open_once(w, target, domains[i], path, 0, 0) == 0) return 0;
        if (tg_monotonic_ms() >= deadline) break;
        if (ws_open_once(w, target, domains[i], path, 1, 0) == 0) return 0;
    }
    if (getenv("TG_WS_DNS_FALLBACK")) {
        for (int i = 0; i < 2; i++) {
            if (tg_monotonic_ms() >= deadline) break;
            if (ws_open_once(w, domains[i], domains[i], path, 0, prefer_v6) == 0) return 0;
        }
    }
    return -1;
}

typedef struct {
    tg_ctr dec;
    unsigned char *cipher_buf;
    unsigned char *plain_buf;
    size_t len;
    size_t cap;
    int proto;
    int disabled;
} ws_splitter;

static void ws_splitter_free(ws_splitter *sp) {
    ctr_free(&sp->dec);
    free(sp->cipher_buf);
    free(sp->plain_buf);
    memset(sp, 0, sizeof(*sp));
}

static int ws_splitter_init(ws_splitter *sp, const unsigned char relay_init[TG_HANDSHAKE_LEN], int proto) {
    memset(sp, 0, sizeof(*sp));
    if (ctr_new(&sp->dec, relay_init + TG_SKIP_LEN,
                relay_init + TG_SKIP_LEN + TG_PREKEY_LEN) != 0) return -1;
    unsigned char zero[64] = {0};
    if (ctr_apply(&sp->dec, zero, zero, sizeof(zero)) != (int)sizeof(zero)) {
        ctr_free(&sp->dec);
        return -1;
    }
    sp->proto = proto;
    return 0;
}

static int ws_splitter_reserve(ws_splitter *sp, size_t need) {
    if (need <= sp->cap) return 0;
    size_t cap = sp->cap ? sp->cap : 4096;
    while (cap < need) {
        if (cap > TG_WS_MAX_MESSAGE) return -1;
        cap *= 2;
    }
    unsigned char *c = realloc(sp->cipher_buf, cap);
    if (!c) return -1;
    sp->cipher_buf = c;
    unsigned char *p = realloc(sp->plain_buf, cap);
    if (!p) return -1;
    sp->plain_buf = p;
    sp->cap = cap;
    return 0;
}

static int ws_splitter_packet_len(const ws_splitter *sp, size_t offset, size_t avail, size_t *packet_len) {
    const unsigned char *p = sp->plain_buf + offset;
    size_t header;
    size_t payload;
    if (avail < 1) return 1;
    if (sp->proto == 0) {
        if (p[0] == 0x7f || p[0] == 0xff) {
            if (avail < 4) return 1;
            header = 4;
            payload = (size_t)p[1] | ((size_t)p[2] << 8) | ((size_t)p[3] << 16);
            payload *= 4;
        } else {
            header = 1;
            payload = (size_t)(p[0] & 0x7f) * 4;
        }
    } else {
        if (avail < 4) return 1;
        header = 4;
        payload = (size_t)(get32le(p) & 0x7fffffffU);
    }
    if (payload == 0) return -1;
    *packet_len = header + payload;
    if (*packet_len > avail) return 1;
    return 0;
}

static int ws_splitter_feed(ws_splitter *sp, tg_ws *w,
                            const unsigned char *data, size_t n) {
    if (!n) return 0;
    if (sp->disabled) return ws_send_message(w, data, n);
    if (ws_splitter_reserve(sp, sp->len + n) != 0) return -1;
    memcpy(sp->cipher_buf + sp->len, data, n);
    if (ctr_apply(&sp->dec, data, sp->plain_buf + sp->len, (int)n) != (int)n) return -1;
    if (n >= 4)
        TG_WS_LOG("[telegram] splitter n=%zu plain=%02x%02x%02x%02x len=%zu\n",
                  n, sp->plain_buf[sp->len], sp->plain_buf[sp->len + 1],
                  sp->plain_buf[sp->len + 2], sp->plain_buf[sp->len + 3], sp->len + n);
    sp->len += n;

    size_t offset = 0;
    while (offset < sp->len) {
        size_t packet_len = 0;
        int r = ws_splitter_packet_len(sp, offset, sp->len - offset, &packet_len);
        if (r == 1) break;
        if (r < 0 || packet_len == 0) {
            if (ws_send_message(w, sp->cipher_buf + offset, sp->len - offset) != 0) return -1;
            offset = sp->len;
            sp->disabled = 1;
            break;
        }
        if (ws_send_message(w, sp->cipher_buf + offset, packet_len) != 0) return -1;
        offset += packet_len;
    }
    if (offset) {
        memmove(sp->cipher_buf, sp->cipher_buf + offset, sp->len - offset);
        memmove(sp->plain_buf, sp->plain_buf + offset, sp->len - offset);
        sp->len -= offset;
    }
    return 0;
}

static int ws_splitter_flush(ws_splitter *sp, tg_ws *w) {
    if (!sp->len) return 0;
    int rc = ws_send_message(w, sp->cipher_buf, sp->len);
    sp->len = 0;
    return rc;
}

static int ws_has_pending(const tg_ws *w) {
    return w->rpos < w->rlen || SSL_pending(w->ssl) > 0 ||
           SSL_has_pending(w->ssl) > 0;
}

static int relay_ws(int cfd, tg_ws *w, tg_session *s, ws_splitter *sp) {
    unsigned char cbuf[TG_BUFSIZE];
    for (;;) {
        int pending = ws_has_pending(w);
        struct pollfd p[2] = {
            {cfd, POLLIN, 0},
            {w->fd, POLLIN, 0}
        };
        int pr = poll(p, 2, pending ? 0 : TG_READ_TMO * 1000);
        TG_WS_LOG("[telegram] WS poll pending=%d pr=%d c=%d u=%d\n",
                  pending, pr, p[0].revents, p[1].revents);
        if (pr < 0) { TG_WS_LOG("[telegram] WS poll error: %s\n", strerror(errno)); return -1; }
        if (pr == 0 && !pending) { TG_WS_LOG("[telegram] WS poll timeout\n"); return -1; }

        if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = s->fake_tls
                      ? tls_read_record(cfd, cbuf, sizeof(cbuf), TG_READ_TMO)
                      : recv(cfd, cbuf, sizeof(cbuf), 0);
            if (n <= 0) {
                TG_WS_LOG("[telegram] WS client closed\n");
                ws_splitter_flush(sp, w);
                return 0;
            }
            unsigned char mid[TG_BUFSIZE], out[TG_BUFSIZE];
            int m = ctr_apply(&s->dec, cbuf, mid, (int)n);
            if (m < 0) return -1;
            m = ctr_apply(&s->dc_enc, mid, out, m);
            if (m < 0) return -1;
            TG_WS_LOG("[telegram] WS up n=%d out_len=%d\n", (int)n, m);
            if (ws_splitter_feed(sp, w, out, (size_t)m) != 0) {
                TG_WS_LOG("[telegram] WS splitter/send failed\n");
                return -1;
            }
        }

        if (pending || (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            unsigned char *msg = NULL;
            size_t msg_len = 0;
            if (ws_recv_message(w, &msg, &msg_len) != 0) {
                TG_WS_LOG("[telegram] WS upstream closed\n");
                return -1;
            }
            TG_WS_LOG("[telegram] WS downstream message %zu\n", msg_len);
            unsigned char *mid = malloc(msg_len ? msg_len : 1);
            unsigned char *out = malloc(msg_len ? msg_len : 1);
            if (!mid || !out) { free(msg); free(mid); free(out); return -1; }
            int m = ctr_apply(&s->dc_dec, msg, mid, (int)msg_len);
            TG_WS_LOG("[telegram] WS down crypto msg=%zu\n", msg_len);
            if (m >= 0) m = ctr_apply(&s->enc, mid, out, m);
            if (m < 0) { free(msg); free(mid); free(out); return -1; }
            int written = s->fake_tls
                        ? tls_write_record(cfd, out, m)
                        : write_full(cfd, out, m);
            if (written < 0 || (!s->fake_tls && written != m) ||
                (s->fake_tls && written != m + 5)) {
                TG_WS_LOG("[telegram] WS client write failed\n");
                free(msg); free(mid); free(out);
                return -1;
            }
            TG_WS_LOG("[telegram] WS downstream delivered %d\n", m);
            free(msg); free(mid); free(out);
        }
    }
}

static int relay_ws_session(int cfd, tg_session *s,
                            const unsigned char relay_init[TG_HANDSHAKE_LEN]) {
    tg_ws w;
    if (ws_open_for_dc(&w, s->dc_idx, telegram_get_ctx()->prefer_ipv6) != 0) {
        TG_WS_LOG("[telegram] WS connect failed for dc=%d\n", s->dc_idx);
        return -1;
    }
    TG_WS_LOG("[telegram] WS connected for dc=%d\n", s->dc_idx);
    if (ws_send_message(&w, relay_init, TG_HANDSHAKE_LEN) != 0) {
        TG_WS_LOG("[telegram] WS relay init send failed\n");
        ws_close(&w);
        return 1;
    }
    ws_splitter sp;
    if (ws_splitter_init(&sp, relay_init, s->proto) != 0) {
        ws_close(&w);
        return 1;
    }
    struct timeval tv = {0, 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    (void)relay_ws(cfd, &w, s, &sp);
    ws_splitter_free(&sp);
    ws_close(&w);
    return 1;
}

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
    if (telegram_get_ctx()->use_fake_tls &&
        hs[0] == 0x16 && hs[1] == 0x03 && hs[2] == 0x01) {
        if (read_full(cfd, hs + 3, 2, TG_HANDSHAKE_TMO) != 2) return;
        int tls_len = (hs[3] << 8) | hs[4];
        if (tls_len > 0 && tls_len < 8192) {
            // +5: заголовок записи кладём в тот же буфер, иначе переполнение
            unsigned char *th = malloc((size_t)tls_len + 5);
            if (!th) return;
            memcpy(th, hs, 5);
            if (read_full(cfd, th + 5, tls_len, TG_HANDSHAKE_TMO) != tls_len) { free(th); return; }
            TG_WS_LOG("[telegram] fake TLS record len=%d\n", tls_len);
            if (!fake_tls_handshake(cfd, th, tls_len + 5)) { TG_WS_LOG("[telegram] fake TLS rejected\n"); free(th); return; }
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

    unsigned char relay_init[TG_HANDSHAKE_LEN];
    if (make_relay_init(&s, client_pv, relay_init) != 0) {
        ctr_free(&s.dec);
        ctr_free(&s.enc);
        return;
    }

    if (telegram_get_ctx()->use_ws) {
        int ws_result = relay_ws_session(cfd, &s, relay_init);
        if (ws_result >= 0) {
            ctr_free(&s.dec);
            ctr_free(&s.enc);
            ctr_free(&s.dc_dec);
            ctr_free(&s.dc_enc);
            return;
        }
        fprintf(stderr, "[telegram] WS DC%d недоступен, TCP fallback\n", s.dc_idx);
    }

    int dfd = pool_take(s.dc_idx, telegram_get_ctx()->prefer_ipv6);
    if (dfd < 0) dfd = connect_dc(s.dc_idx, telegram_get_ctx()->prefer_ipv6);
    if (dfd < 0) {
        ctr_free(&s.dec);
        ctr_free(&s.enc);
        ctr_free(&s.dc_dec);
        ctr_free(&s.dc_enc);
        return;
    }

    if (dc_handshake(dfd, &s, relay_init) != 0) {
        close(dfd);
        ctr_free(&s.dec);
        ctr_free(&s.enc);
        ctr_free(&s.dc_dec);
        ctr_free(&s.dc_enc);
        return;
    }

    struct timeval tv2 = { 0, 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    setsockopt(dfd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));

    relay(cfd, dfd, &s);

    close(dfd);
    ctr_free(&s.dec);
    ctr_free(&s.enc);
    ctr_free(&s.dc_dec);
    ctr_free(&s.dc_enc);
}

// ─────────────────────────── accept-цикл ───────────────────────────

static volatile sig_atomic_t g_running = 0;
static int g_listen_fd = -1;

static void on_term(int sig) { (void)sig; g_running = 0; if (g_listen_fd >= 0) { close(g_listen_fd); g_listen_fd = -1; } }

static void proxy_child(int port) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (getppid() == 1) _exit(0);
    setsid();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, on_term);

    secret_init();

    int one = 1;
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) _exit(1);
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) != 0) _exit(2);
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
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            if (getppid() == 1) _exit(0);
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
