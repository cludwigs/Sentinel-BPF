#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"
#include "edr_lsm.skel.h"

static volatile sig_atomic_t exiting = 0;

static const char *event_name(unsigned int event_type) {
    switch (event_type) {
    case EVENT_EXEC_ATTEMPT:
        return "EXEC_ATTEMPT";
    case EVENT_MEMORY_EXEC:
        return "MEMORY_EXEC";
    case EVENT_PTRACE_ACCESS:
        return "PTRACE_ACCESS";
    case EVENT_SHELLCODE_INJECT:
        return "SHELLCODE_INJECTION";
    case EVENT_SOCKET_CONNECT:
        return "SOCKET_CONNECT";
    case EVENT_PRIV_ESCALATION:
        return "PRIV_ESCALATION";
    default:
        return "UNKNOWN";
    }
}

static const char *severity_name(unsigned int severity) {
    switch (severity) {
    case EVENT_INFO:
        return "INFO";
    case EVENT_WARNING:
        return "WARNING";
    case EVENT_CRITICAL:
        return "CRITICAL";
    default:
        return "UNKNOWN";
    }
}

static const char *action_name(unsigned int action) {
    switch (action) {
    case ACTION_ALLOW:
        return "ALLOW";
    case ACTION_ALERT:
        return "ALERT";
    case ACTION_BLOCK:
        return "BLOCK";
    default:
        return "UNKNOWN";
    }
}

static void sig_handler(int sig) {
    exiting = 1;
}

static int add_blocked_binary(int map_fd, const char *name) {
    struct block_key key = {0};
    struct block_value val = { .flags = 1 };

    strncpy(key.filename, name, sizeof(key.filename) - 1);

    int err = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
    if (err) {
        fprintf(stderr, "[-] Échec de l'ajout de %s à la blacklist: %d\n", name, err);
        return err;
    }
    printf("[+] Règle appliquée à chaud : blocage de '%s'\n", name);
    return 0;
}

static void load_default_policy(int map_fd) {
    static const char *blocked[] = {
        "nc",
        "ncat",
        "netcat",
        "socat",
        "nc.openbsd",
        "nc.traditional",
        NULL
    };

    for (int i = 0; blocked[i] != NULL; ++i) {
        add_blocked_binary(map_fd, blocked[i]);
    }
}

static void load_jit_allowlist(int map_fd) {
    static const char *allowed_comms[] = {
        "node",
        "java",
        "python3",
        "firefox",
        "chrome",
        NULL
    };

    for (int i = 0; allowed_comms[i] != NULL; ++i) {
        struct allow_comm_key key = {0};
        strncpy(key.comm, allowed_comms[i], sizeof(key.comm) - 1);
        unsigned int val = 1;
        bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
    }
    printf("[+] Whitelist JIT chargée (process autorisés à mprotect EXEC).\n");
}

static int remove_blocked_binary(int map_fd, const char *name) {
    struct block_key key = {0};
    strncpy(key.filename, name, sizeof(key.filename) - 1);

    int err = bpf_map_delete_elem(map_fd, &key);
    if (err) {
        fprintf(stderr, "[-] Impossible de retirer %s: %d\n", name, err);
        return err;
    }
    printf("[*] Règle retirée : '%s' de nouveau autorisé\n", name);
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct block_event *e = data;

    if (e->event_type == EVENT_MEMORY_EXEC) {
        printf("\033[1;33m[MEMORY]\033[0m PID %d (%s) : exécution depuis mémoire détectée (prot=0x%x) -> %s\n",
               e->pid, e->comm, e->prot, action_name(e->action));
        return 0;
    }

    if (e->event_type == EVENT_PTRACE_ACCESS) {
        printf("\033[1;35m[PTRACE]\033[0m PID %d (%s) tente d'accéder à PID %d via ptrace [%s/%s] -> %s\n",
               e->pid,
               e->comm,
               e->target_pid,
               severity_name(e->severity),
               action_name(e->action),
               action_name(e->action));
        return 0;
    }

    if (e->event_type == EVENT_SHELLCODE_INJECT) {
        printf("\033[1;31m[SHELLCODE]\033[0m PID %d (%s) : écriture + exécution mémoire (W+X) détectée (prot=0x%x) -> %s\n",
               e->pid,
               e->comm,
               e->prot,
               action_name(e->action));
        return 0;
    }

    if (e->event_type == EVENT_SOCKET_CONNECT) {
        char ip_str[INET_ADDRSTRLEN] = {0};
        struct in_addr addr = { .s_addr = e->daddr };
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

        if (e->severity == EVENT_CRITICAL) {
            printf("\033[1;31m[NET-SUSPECT]\033[0m PID %d (%s) se connecte vers %s:%u [%s/%s]\n",
                   e->pid, e->comm, ip_str, e->dport, severity_name(e->severity), action_name(e->action));
        } else {
            printf("\033[1;36m[NET-CONNECT]\033[0m PID %d (%s) se connecte vers %s:%u\n",
                   e->pid, e->comm, ip_str, e->dport);
        }
        return 0;
    }

    if (e->event_type == EVENT_PRIV_ESCALATION) {
        printf("\033[1;41;37m[PRIV_ESCALATION]\033[0m PID %d (%s) : passage de UID %u à ROOT (UID 0) détecté ! [%s/%s]\n",
               e->pid, e->comm, e->prot, severity_name(e->severity), action_name(e->action));
        return 0;
    }

    if (e->blocked) {
        printf("\033[1;31m[BLOCKED]\033[0m PID %d (%s) [%s/%s/%s] a tenté d'exécuter: %s -> %s\n",
               e->pid,
               e->comm,
               event_name(e->event_type),
               severity_name(e->severity),
               action_name(e->action),
               e->filename,
               action_name(e->action));
    } else {
        printf("[OK] PID %d (%s) [%s/%s/%s] -> %s\n",
               e->pid,
               e->comm,
               event_name(e->event_type),
               severity_name(e->severity),
               action_name(e->action),
               e->filename);
    }
    return 0;
}

int main(void) {
    struct edr_lsm_bpf *skel;
    struct ring_buffer *rb = NULL;
    int denied_map_fd, allow_map_fd, err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = edr_lsm_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Erreur chargement eBPF LSM.\n");
        return 1;
    }

    denied_map_fd = bpf_map__fd(skel->maps.denied_binaries);
    load_default_policy(denied_map_fd);

    allow_map_fd = bpf_map__fd(skel->maps.mprotect_allowlist);
    load_jit_allowlist(allow_map_fd);

    err = edr_lsm_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Erreur attachement LSM: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        goto cleanup;
    }

    printf("[*] Sentinel-BPF actif. Surveillance LSM en cours...\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break;
        if (err < 0) break;
    }

cleanup:
    ring_buffer__free(rb);
    edr_lsm_bpf__destroy(skel);
    return 0;
}
