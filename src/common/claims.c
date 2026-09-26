#include "src/common/claims.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#define CLAIMS_ROOT "/run/rmf/claims"

static int ensure_root(void) {
    if (mkdir("/run/rmf", 0755) != 0 && errno != EEXIST) return -1;
    if (mkdir(CLAIMS_ROOT, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static void path_for(const char *module, char *out, size_t n) {
    snprintf(out, n, "%s/%s", CLAIMS_ROOT, module);
}

int claims_store(const char *module, const char *const *ips, size_t count) {
    if (!module || !*module) return -1;
    if (strchr(module, '/')) return -1;              // без путей в имени
    if (ensure_root() != 0) return -1;

    char path[512];
    path_for(module, path, sizeof(path));
    char tmp[520];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    for (size_t i = 0; ips && i < count && ips[i]; i++)
        fprintf(f, "%s\n", ips[i]);
    fclose(f);
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

int claims_taken_by_other(const char *module, const char *ip) {
    if (!module || !ip || !*ip) return 0;
    DIR *d = opendir(CLAIMS_ROOT);
    if (!d) return 0;                               // реестра нет — не конфликтуем
    int taken = 0;
    struct dirent *e;
    while (!taken && (e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        if (strcmp(e->d_name, module) == 0) continue;
        char path[600];
        snprintf(path, sizeof(path), "%s/%s", CLAIMS_ROOT, e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            size_t l = strlen(line);
            while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
            if (l && strcasecmp(line, ip) == 0) { taken = 1; break; }
        }
        fclose(f);
    }
    closedir(d);
    return taken;
}

void claims_release(const char *module) {
    if (!module || !*module) return;
    char path[512];
    path_for(module, path, sizeof(path));
    unlink(path);
}
