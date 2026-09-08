#include "vmlinux.h"

/* Types UAPI / Kernel de base requis par libbpf_helpers */
typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;

typedef signed char         __s8;
typedef short               __s16;
typedef int                 __s32;
typedef long long           __s64;

typedef __u16               __be16;
typedef __u32               __be32;
typedef __u64               __be64;
typedef __u32               __wsum;

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define EPERM 1

char LICENSE[] SEC("license") = "GPL";

// Map de hachage dynamique gérée par le User-Space
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct block_key);
    __type(value, struct block_value);
} denied_binaries SEC(".maps");

// Ring Buffer pour les alertes
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline void submit_exec_event(struct block_key *key, int blocked, unsigned int severity, unsigned int action, unsigned int event_type, unsigned int prot) {
    struct block_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 id = bpf_get_current_pid_tgid();

    e->pid = id >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->target_pid = 0;
    e->blocked = blocked;
    e->event_type = event_type;
    e->severity = severity;
    e->action = action;
    e->prot = prot;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    if (key != NULL) {
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), key->filename);
    } else {
        __builtin_memset(e->filename, 0, sizeof(e->filename));
    }

    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_execution, struct linux_binprm *bprm, int ret) {
    if (ret != 0) {
        return ret;
    }

    struct block_key key = {0};
    const unsigned char *filename_ptr = BPF_CORE_READ(bprm, file, f_path.dentry, d_name.name);

    bpf_probe_read_kernel_str(&key.filename, sizeof(key.filename), (const void *)filename_ptr);

    struct block_value *rule = bpf_map_lookup_elem(&denied_binaries, &key);
    int block = (rule != NULL);

    unsigned int evt_severity = block ? EVENT_CRITICAL : EVENT_INFO;
    unsigned int evt_action = block ? ACTION_BLOCK : ACTION_ALLOW;

    submit_exec_event(&key, block, evt_severity, evt_action, EVENT_EXEC_ATTEMPT, 0);

    if (block) {
        return -EPERM;
    }

    return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(file_mprotect, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot, unsigned long flags) {
    unsigned long permissions = reqprot | prot;
    int block = 0;

    /* Heuristique critique : détection W+X (PROT_WRITE | PROT_EXEC) */
    if (((permissions & 0x6) == 0x6) && (permissions & 0x4)) {
        struct block_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            u64 id = bpf_get_current_pid_tgid();

            e->pid = id >> 32;
            e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            e->ppid = BPF_CORE_READ(task, real_parent, tgid);
            e->target_pid = 0;
            e->blocked = 1;
            e->event_type = EVENT_SHELLCODE_INJECT;
            e->severity = EVENT_CRITICAL;
            e->action = ACTION_BLOCK;
            e->prot = (unsigned int)permissions;
            __builtin_memset(e->comm, 0, sizeof(e->comm));
            __builtin_memset(e->filename, 0, sizeof(e->filename));
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
        return -EPERM;
    }
    /* Surveillance : allocation/modification de mémoire exécutable simple */
    else if ((permissions & 0x4) != 0) {
        struct block_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            u64 id = bpf_get_current_pid_tgid();

            e->pid = id >> 32;
            e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            e->ppid = BPF_CORE_READ(task, real_parent, tgid);
            e->target_pid = 0;
            e->blocked = 0;
            e->event_type = EVENT_MEMORY_EXEC;
            e->severity = EVENT_WARNING;
            e->action = ACTION_ALERT;
            e->prot = (unsigned int)permissions;
            __builtin_memset(e->comm, 0, sizeof(e->comm));
            __builtin_memset(e->filename, 0, sizeof(e->filename));
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace_entry(struct trace_event_raw_sys_enter *ctx) {
    long request = (long)ctx->args[0];
    long pid = (long)ctx->args[1];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 id = bpf_get_current_pid_tgid();

    if (request == 0 || pid == 0) {
        return 0;
    }

    struct block_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = id >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->target_pid = (int)pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->blocked = 1;
    e->event_type = EVENT_PTRACE_ACCESS;
    e->severity = EVENT_CRITICAL;
    e->action = ACTION_BLOCK;
    e->prot = (unsigned int)request;
    __builtin_memset(e->comm, 0, sizeof(e->comm));
    __builtin_memset(e->filename, 0, sizeof(e->filename));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, unsigned int mode) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 id = bpf_get_current_pid_tgid();
    pid_t target_pid = BPF_CORE_READ(child, tgid);

    /* Ne pas s'alerter si un processus inspecte son propre thread / process */
    if ((id >> 32) == target_pid) {
        return 0;
    }

    struct block_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = id >> 32;
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);
        e->target_pid = target_pid;
        e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        e->blocked = 1;
        e->event_type = EVENT_PTRACE_ACCESS;
        e->severity = EVENT_CRITICAL;
        e->action = ACTION_BLOCK;
        e->prot = mode;
        __builtin_memset(e->comm, 0, sizeof(e->comm));
        __builtin_memset(e->filename, 0, sizeof(e->filename));
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return -EPERM;
}
