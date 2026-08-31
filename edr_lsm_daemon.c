#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
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
        printf("\033[1;31m[SHELLCODE]\033[0m PID %d (%s) : écriture + exécution mémoire détectée (prot=0x%x) -> %s\n",
               e->pid,
               e->comm,
               e->prot,
               action_name(e->action));
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
    int map_fd, err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = edr_lsm_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Erreur chargement eBPF LSM.\n");
        return 1;
    }

    map_fd = bpf_map__fd(skel->maps.denied_binaries);
    load_default_policy(map_fd);

    err = edr_lsm_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Erreur attachement LSM: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        goto cleanup;
    }

    printf("[*] EDR actif. Essayez de lancer 'nc' ou 'socat' dans un autre terminal.\n");
    printf("[*] La détection mémoire exécutable est activée en mode surveillance.\n");

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
