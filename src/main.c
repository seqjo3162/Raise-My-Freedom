#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <dirent.h>
#include <libgen.h>
#include "src/plugin_api.h"

static volatile int s_running = 1;
static void on_signal(int sig) { (void)sig; s_running = 0; }

static int plugin_status_failed(const char *status) {
    if (!status) return 0;
    return strstr(status, "down") || strstr(status, "Inactive") ||
           strstr(status, "Unavailable") || strstr(status, "failed") ||
           strstr(status, "Idle") || strstr(status, "Not loaded") ||
           strcmp(status, "Off") == 0;
}

extern int run_proxy(int argc, char **argv);

typedef void (*plug_init_fn)(void*);
typedef void (*plug_inject_fn)(int);
typedef void (*plug_cleanup_fn)(void);
typedef const char* (*plug_name_fn)(void);
typedef const char* (*plug_status_fn)(void);

typedef struct {
    void* handle;
    char name[64];
    plug_init_fn init;
    plug_inject_fn inject;
    plug_cleanup_fn cleanup;
    plug_name_fn get_name;
    plug_status_fn get_status;
    char path[1024];
} plugin_t;

static plugin_t plugin = {0};
static char plugs_dir[1024];
static char saved_resolv[4096] = {0};
static int resolv_saved = 0;
static char ifname[64] = "enp42s0";

static void detect_interface(void) {
    FILE *fp = popen("ip route show default 2>/dev/null | awk '{print $5; exit}'", "r");
    if (fp) {
        char buf[64] = {0};
        if (fgets(buf, sizeof(buf), fp)) {
            buf[strcspn(buf, "\n")] = 0;
            if (buf[0]) snprintf(ifname, sizeof(ifname), "%s", buf);
        }
        pclose(fp);
    }
}

static void find_plugs_dir(void) {
    char exe_path[1024];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        snprintf(plugs_dir, sizeof(plugs_dir), "%s/plugs", dirname(exe_path));
    } else {
        strcpy(plugs_dir, "build/bin/plugs");
    }
}

static void run_command(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

static void setup_dns(void) {
    detect_interface();
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "resolvectl dns %s 2>/dev/null", ifname);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        size_t n = fread(saved_resolv, 1, sizeof(saved_resolv) - 1, fp);
        saved_resolv[n] = 0;
        resolv_saved = 1;
        pclose(fp);
    }
    snprintf(cmd, sizeof(cmd), "resolvectl dns %s 127.0.0.1 2>/dev/null", ifname);
    run_command(cmd);
    fprintf(stderr, "[MAIN] DNS -> 127.0.0.1 (interface: %s)\n", ifname);
}

static void restore_dns(void) {
    if (!resolv_saved) return;
    char cmd[512];
    const char *p = strstr(saved_resolv, "DNS Servers:");
    if (p) {
        p += 12;
        while (*p == ' ') p++;
        char servers[256] = {0};
        int i = 0;
        while (p[i] && p[i] != '\n' && i < 255) { servers[i] = p[i]; i++; }
        servers[i] = 0;
        snprintf(cmd, sizeof(cmd), "resolvectl dns %s %s 2>/dev/null", ifname, servers);
        run_command(cmd);
        fprintf(stderr, "[MAIN] DNS restored: %s\n", servers);
    }
}

static int load_plugin(const char *name) {
    const char *canonical_name = plugin_canonical_name(name);
    if (!plugin_name_valid(canonical_name)) {
        fprintf(stderr, "[PLUGIN] invalid name: %s\n", name ? name : "");
        return -1;
    }

    if (plugin.handle) {
        plugin.cleanup();
        dlclose(plugin.handle);
        memset(&plugin, 0, sizeof(plugin));
    }

    int path_length = snprintf(plugin.path, sizeof(plugin.path), "%s/%s.xo", plugs_dir, canonical_name);
    if (path_length < 0 || (size_t)path_length >= sizeof(plugin.path)) {
        fprintf(stderr, "[PLUGIN] name too long: %s\n", canonical_name);
        return -1;
    }
    strncpy(plugin.name, canonical_name, sizeof(plugin.name) - 1);

    plugin.handle = dlopen(plugin.path, RTLD_NOW);
    if (!plugin.handle) {
        fprintf(stderr, "[PLUGIN] load failed %s: %s\n", plugin.path, dlerror());
        return -1;
    }

    plugin.init = (plug_init_fn)dlsym(plugin.handle, "plug_init");
    plugin.inject = (plug_inject_fn)dlsym(plugin.handle, "plug_inject");
    plugin.cleanup = (plug_cleanup_fn)dlsym(plugin.handle, "plug_cleanup");
    plugin.get_name = (plug_name_fn)dlsym(plugin.handle, "plug_name");
    plugin.get_status = (plug_status_fn)dlsym(plugin.handle, "plug_status");

    if (!plugin.init || !plugin.inject || !plugin.cleanup) {
        fprintf(stderr, "[PLUGIN] missing plug_init/plug_inject/plug_cleanup in %s\n", canonical_name);
        dlclose(plugin.handle);
        memset(&plugin, 0, sizeof(plugin));
        return -1;
    }

    fprintf(stderr, "[PLUGIN] loaded: %s (%s)\n", canonical_name, plugin.path);
    return 0;
}

static void list_plugins(void) {
    DIR *dir = opendir(plugs_dir);
    if (!dir) {
        fprintf(stderr, "[PLUGIN] directory not found: %s\n", plugs_dir);
        return;
    }

    fprintf(stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    fprintf(stderr, "  📦 Available plugins:\n");
    fprintf(stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".xo")) {
            char plugin_file_name[256];
            snprintf(plugin_file_name, sizeof(plugin_file_name), "%s", entry->d_name);
            char *dot = strstr(plugin_file_name, ".xo");
            if (dot) *dot = '\0';
            if (strcmp(plugin_canonical_name(plugin_file_name), plugin_file_name) != 0) continue;

            char fullpath[1024];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", plugs_dir, entry->d_name);

            void *h = dlopen(fullpath, RTLD_NOW);
            if (h) {
                plug_name_fn pn = (plug_name_fn)dlsym(h, "plug_name");
                const char *pname = pn ? pn() : entry->d_name;
                fprintf(stderr, "  ✅ %-20s  %s\n", pname, entry->d_name);
                dlclose(h);
            } else {
                fprintf(stderr, "  ❌ %-20s  %s (broken)\n", entry->d_name, entry->d_name);
            }
            count++;
        }
    }
    closedir(dir);

    if (count == 0) fprintf(stderr, "  (no plugins found)\n");
    fprintf(stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

int main(int argc, char **argv) {
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    find_plugs_dir();

    if (argc < 2) goto usage;

    if (strcmp(argv[1], "proxy") == 0)
        return run_proxy(argc, argv);

    if (strcmp(argv[1], "list") == 0) {
        list_plugins();
        return 0;
    }

    if (strcmp(argv[1], "plugin") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: %s plugin --<plugin>\n", argv[0]); return 1; }
        const char *mod = argv[2];
        while (*mod == '-') mod++;

        if (load_plugin(mod) < 0) return 1;

        fprintf(stderr, "[PLUGIN] Injecting: %s\n", plugin.name);
        plugin.init(NULL);
        plugin.inject(-1);
        if (plugin.get_status) {
            const char *status = plugin.get_status();
            if (plugin_status_failed(status)) {
                fprintf(stderr, "[PLUGIN] %s unavailable after inject: %s\n", plugin.name, status);
                plugin.cleanup();
                dlclose(plugin.handle);
                memset(&plugin, 0, sizeof(plugin));
                return 1;
            }
        }

        fprintf(stderr, "[PLUGIN] %s running. Waiting for signal.\n", plugin.name);
        while (s_running) {
            poll(NULL, 0, 500);
            if (plugin.get_status && plugin_status_failed(plugin.get_status()))
                s_running = 0;
        }

        fprintf(stderr, "[PLUGIN] Cleaning up %s...\n", plugin.name);
        plugin.cleanup();
        dlclose(plugin.handle);
        memset(&plugin, 0, sizeof(plugin));
        fprintf(stderr, "[PLUGIN] %s stopped.\n", plugin.name);
        return 0;
    }

    if (strcmp(argv[1], "inject") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: %s inject --<plugin>\n", argv[0]); return 1; }
        const char *mod = argv[2];
        while (*mod == '-') mod++;

        const char *old_chains[] = {
            "GITHUB_BYPASS", "DISCORD_BYPASS",
            "VRCHAT_BYPASS",
            "GOOGLE_YT_BYPASS",
            "XCOM_BYPASS",
            "SPEEDTEST_BYPASS",
            "MINIZAPRET_DNS",
            "ACTIVISION_BYPASS",
            "BATTLENET_BYPASS",
            "ELECTRONICARTS_BYPASS",
            "EPICGAMES_BYPASS",
            "ROBLOX_BYPASS",
            "SOUNDCLOUD_BYPASS",
            "STEAM_BYPASS",
            "TWITCH_BYPASS",
            NULL
        };
        for (int i = 0; old_chains[i]; i++) {
            char command[256];
            snprintf(command, sizeof(command),
                     "iptables -t nat -D OUTPUT -j %s 2>/dev/null; "
                     "iptables -t nat -F %s 2>/dev/null; "
                     "iptables -t nat -X %s 2>/dev/null",
                     old_chains[i], old_chains[i], old_chains[i]);
            run_command(command);
        }
        fprintf(stderr, "[MAIN] Old iptables rules flushed\n");

        if (load_plugin(mod) < 0) return 1;

        char port_str[16]; snprintf(port_str, sizeof(port_str), "%d", 53);
        pid_t proxy_pid = fork();
        if (proxy_pid == 0) {
            execl(argv[0], argv[0], "proxy", "--port", port_str, "--upstream", "1.1.1.1", "--fallback", "8.8.8.8", NULL);
            fprintf(stderr, "[MAIN] execl proxy failed: %s\n", strerror(errno));
            _exit(1);
        }
        if (proxy_pid < 0) { perror("fork"); return 1; }
        fprintf(stderr, "[MAIN] Proxy PID: %d\n", proxy_pid);
        sleep(1);

        setup_dns();

        fprintf(stderr, "[MAIN] Injecting: %s\n", mod);
        plugin.init(NULL);
        plugin.inject(-1);

        fprintf(stderr, "[MAIN] Running. Ctrl+C to stop.\n");
        while (s_running) poll(NULL, 0, 500);

        fprintf(stderr, "\n[MAIN] Stopping...\n");
        plugin.cleanup();
        dlclose(plugin.handle);
        memset(&plugin, 0, sizeof(plugin));

        restore_dns();
        kill(proxy_pid, SIGTERM);
        waitpid(proxy_pid, NULL, 0);
        fprintf(stderr, "[MAIN] Done.\n");
        return 0;
    }

usage:
    fprintf(stderr,
        "minizapret — DNS bypass for blocked services (plugin system)\n\n"
        "Usage:\n"
        "  %s inject --<plugin>   Load plugin and start DNS bypass\n"
        "  %s list                List available plugins\n"
        "  %s proxy               Standalone DNS proxy (internal)\n\n"
        "Plugins directory: %s/\n",
        argv[0], argv[0], argv[0], plugs_dir);
    return 0;
}
