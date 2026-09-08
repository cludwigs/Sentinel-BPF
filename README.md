# Sentinel-BPF

Sentinel-BPF is a Linux security proof of concept built with eBPF and Linux Security Module hooks.

The project demonstrates how a kernel-side monitor can detect and block suspicious execution patterns, observe executable memory usage, and identify cross-process memory access attempts. It is designed as an educational and research-oriented prototype for advanced Linux security controls.

## What is implemented

The project currently includes the following features.

### 1. Binary execution blocking

The kernel component is attached to the LSM hook `bprm_check_security`.

It does the following:

- reads the target executable name from the process `binprm`
- checks the name against a BPF hash map of blocked binaries
- returns `-EPERM` when a denied binary is about to run
- emits a structured event into a ring buffer

This means the project already provides a functional denylist-based execution guard.

### 2. Denylist policy loaded by the daemon

The user-space daemon loads the BPF object, opens the denylist map, and inserts default entries such as `nc`, `ncat`, `netcat`, `socat`, and related variants.

This creates a basic active policy layer without recompiling the kernel program each time.

### 3. Event enrichment

The shared structures in [common.h](common.h) now include richer metadata for events:

- event type
- severity
- action
- target process identifier
- memory protection flags

This allows the system to distinguish between execution attempts, memory execution patterns, and suspicious cross-process behaviors.

### 4. Memory execution detection

The project now monitors executable memory-related protections through the LSM hook associated with memory protection updates.

It raises an alert when protection flags include executable permissions, and it classifies suspicious combinations as a higher-risk signal.

This is an important step toward behavior-based detection of code injection.

### 5. Shellcode-like behavioral detection & prevention

A behavioral rule prevents and alerts on the classic “write + execute” memory pattern.
- When an `mprotect` call attempts to set both `PROT_WRITE` and `PROT_EXEC`, the operation is blocked in kernel-space by returning `-EPERM`.
- A structured critical event is submitted to user space to log the attempt.
- Regular executable mapping changes are logged separately as warning alerts without emitting duplicate events.

### 6. Cross-process access prevention (LSM)

Cross-process inspection and injection attempts via `ptrace` are intercepted directly through the `ptrace_access_check` LSM hook.
- Targets are verified in-kernel through the target `task_struct`.
- Unauthorized ptrace attachments are blocked at the LSM boundary (`-EPERM`).

---

## What is still limited

The current project remains a prototype and is not a complete EDR or anti-malware engine.

Main limitations:

- detection is heuristic, not signature-based or fully behavioral for all payload types
- memory analysis is still simple and could generate false positives for legitimate JIT or runtime behavior
- process tracing detection is only a first layer; it does not yet discriminate trusted parent-child processes properly
- policy is still largely static and not fully externalized into a config file
- no centralized alert pipeline, correlation engine, or persisted telemetry storage exists yet

---

## Project architecture

### Kernel side

The main logic is in [edr_lsm.bpf.c](edr_lsm.bpf.c).

It contains:

- execution blocking through `bprm_check_security`
- denylist lookup with a BPF hash map
- ring buffer event emission
- executable-memory monitoring and W+X blocking in `file_mprotect`
- ptrace access prevention via `lsm/ptrace_access_check`

### User-space side

The daemon in [edr_lsm_daemon.c](edr_lsm_daemon.c) is responsible for:

- loading the BPF program
- attaching the LSM hooks
- populating the initial denylist
- polling and printing the ring-buffer events
- presenting security telemetry in a readable format

### Shared definitions

The structures in [common.h](common.h) define the shared model between kernel and user space, including event categories and security metadata.

---

## Why this matters

This project is interesting because it demonstrates a realistic kernel-side security model:

- monitor a critical execution path in the kernel
- block unwanted programs before they run
- detect memory execution patterns
- observe suspicious inter-process interaction
- stream telemetry to user space in low-overhead mode

This is very close in spirit to how modern security products inspect high-risk events at the kernel boundary.

---

## Difficulty level

This is a medium-to-high difficulty project.

Reasons:

- eBPF and kernel hooks are complex
- LSM and syscall tracepoints require careful compatibility handling
- memory protection and process instrumentation are error-prone
- Linux kernel semantics can vary by version and distro

---

## Requirements

This project is intended for Linux systems with:

- root or equivalent privileges
- modern kernel support for eBPF and LSM hooks
- `clang`
- `bpftool`
- `libbpf` and development headers

---

## Build

```bash
make
```

This compiles the BPF object and the user-space daemon.

---

## Run

```bash
sudo ./edr_lsm_daemon
```

Then, from another terminal, try a blocked binary such as:

```bash
nc
```

or:

```bash
socat
```

You should observe blocking and alert output from the daemon.

---

## Example output

```text
[+] Règle appliquée à chaud : blocage de 'nc'
[*] EDR actif. Essayez de lancer 'nc' ou 'socat' dans un autre terminal.
[*] La détection mémoire exécutable est activée en mode surveillance.
[BLOCKED] PID 1234 (bash) [EXEC_ATTEMPT/CRITICAL/BLOCK] a tenté d'exécuter: nc -> BLOCK
[MEMORY] PID 5678 (python) : exécution depuis mémoire détectée (prot=0x4) -> ALERT
[PTRACE] PID 9001 (bash) tente d'accéder à PID 2345 via ptrace [CRITICAL/BLOCK] -> BLOCK
[SHELLCODE] PID 4321 (python) : écriture + exécution mémoire détectée (prot=0x6) -> BLOCK
```

---

## Recommended next improvements

The best next steps are:

1. add a real policy file and runtime reload support
2. refine memory heuristics to reduce false positives
3. distinguish trusted parent-child ptrace flows from malicious ones
4. add a risk score and event correlation model
5. move from alerting to configurable blocking rules for memory-executable abuse
6. persist logs and expose them to a central collector or SIEM

---

## Security note

This project interacts with kernel execution and process control paths. It is intended for research, learning, and controlled lab environments only.

Use it responsibly and do not deploy it on production systems without careful validation.

---

## Conclusion

Sentinel-BPF is now a stronger kernel-level security prototype than the initial version.

It already includes:

- denylist-based binary blocking
- memory execution alerts
- shellcode-like malicious behavior heuristics
- ptrace-based cross-process injection detection

This makes the project a much better foundation for further development toward a fuller Linux EDR-style defense system.
