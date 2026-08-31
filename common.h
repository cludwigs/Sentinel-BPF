#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN  128

#define EVENT_EXEC_ATTEMPT       1u
#define EVENT_MEMORY_EXEC        2u
#define EVENT_PTRACE_ACCESS      3u
#define EVENT_SHELLCODE_INJECT   4u

#define EVENT_INFO     0u
#define EVENT_WARNING  1u
#define EVENT_CRITICAL 2u

#define ACTION_ALLOW   0u
#define ACTION_ALERT   1u
#define ACTION_BLOCK   2u

// Clé de la Map : le chemin ou nom du binaire à bloquer
struct block_key {
    char filename[PATH_MAX_LEN];
};

// Valeur associée : 1 pour actif (permet d'étendre avec des flags de sévérité plus tard)
struct block_value {
    unsigned int flags;
};

// Structure d'événement RingBuffer
struct block_event {
    int pid;
    int ppid;
    int target_pid;
    unsigned int uid;
    char comm[TASK_COMM_LEN];
    char filename[PATH_MAX_LEN];
    int blocked;
    unsigned int event_type;
    unsigned int severity;
    unsigned int action;
    unsigned int prot;
};

#endif
