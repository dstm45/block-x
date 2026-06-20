# Observing System Calls for eBPF-based HIDS

When building a Host Intrusion Detection System (HIDS) using eBPF, monitoring the right system calls is essential. System calls act as the boundary between user space applications and the Linux kernel, making them the ideal vantage point for security auditing.

Below is an architectural guide to the top system calls you should observe, categorized by security domains, along with their detection relevance, heuristics, and eBPF instrumentation strategies.

---

## 1. Process Lifecycle & Execution (Execution & Initial Access)

Detecting when and how programs are executed is the foundation of process lineage tracking and detecting unauthorized execution.

| Syscall | Hook / Event Type | Detection Relevance | Security Heuristics |
| :--- | :--- | :--- | :--- |
| **`execve`** / **`execveat`** | `tracepoint/syscalls/sys_enter_execve`<br>`lsm/bprm_check_security` | Executing a new program. Replaces the current process image. | • Run binary paths against blocklists/allowlists.<br>• Analyze arguments (`argv`) for malicious flags (e.g., `bash -i`, curl to external IPs).<br>• Detect unusual parent-child relationships (e.g., `nginx` spawning `sh`). |
| **`clone`** / **`clone3`** / **`fork`** | `tracepoint/syscalls/sys_enter_clone` | Creation of new processes or threads. | • Map process trees (PID namespace monitoring).<br>• Monitor container escapes (creation of processes outside the container namespace). |
| **`exit`** / **`exit_group`** | `tracepoint/syscalls/sys_enter_exit_group` | Termination of a process. | • Clean up process maps inside the eBPF kernel state to prevent memory leaks.<br>• Correlate lifespan of short-lived processes (often indicators of automated scanning or exploit payloads). |

---

## 2. File System Operations (Persistence & Credential Access)

File system monitoring tracks unauthorized modifications of system configurations, credential dumping, and defense evasion.

| Syscall | Hook / Event Type | Detection Relevance | Security Heuristics |
| :--- | :--- | :--- | :--- |
| **`open`** / **`openat`** / **`openat2`** | `tracepoint/syscalls/sys_enter_openat`<br>`lsm/file_open` | Opening files for reading, writing, or creation. | • Access to sensitive files (e.g., `/etc/shadow`, `/etc/passwd`, `/root/.ssh/authorized_keys`, TLS private keys).<br>• Access to database files by non-database processes. |
| **`write`** / **`pwrite64`** / **`writev`** | `tracepoint/syscalls/sys_enter_write`<br>`lsm/file_permission` | Modifying files or streams. | • Integrity monitoring: Writes to binary directories (e.g., `/bin/`, `/usr/bin/`) or system configurations (e.g., `/etc/pam.d/`, `/etc/cron*`). |
| **`unlink`** / **`unlinkat`** / **`rmdir`** | `tracepoint/syscalls/sys_enter_unlink` | Deleting files or directories. | • Timestamps/Log clearing (deleting logs in `/var/log`).<br>• Self-deleting malware (binary unlinked immediately after execution to run purely in memory). |
| **`chmod`** / **`fchmod`** / **`chown`** | `tracepoint/syscalls/sys_enter_chmod` | Changing permissions or owners of files. | • Files being made executable (e.g., changing permissions on downloaded files in `/tmp` to `+x`). |

---

## 3. Network Operations (Command & Control, Exfiltration)

Monitoring socket creation and connections is critical for identifying reverse shells, backdoors, and data exfiltration.

| Syscall | Hook / Event Type | Detection Relevance | Security Heuristics |
| :--- | :--- | :--- | :--- |
| **`socket`** | `tracepoint/syscalls/sys_enter_socket`<br>`lsm/socket_create` | Allocating a network endpoint (TCP, UDP, Raw). | • Non-network daemons (like databases or text editors) creating sockets.<br>• Use of Raw sockets (`SOCK_RAW`), which can be used for sniffing or crafting custom packets. |
| **`connect`** | `tracepoint/syscalls/sys_enter_connect`<br>`lsm/socket_connect` | Initiating an active outbound connection to a remote host. | • Capture remote IP addresses, ports, and protocols.<br>• Correlate with threat intelligence to detect connections to known Command and Control (C2) servers. |
| **`bind`** / **`listen`** | `tracepoint/syscalls/sys_enter_bind` | Registering a local port / listening for inbound connections. | • Unauthorized processes attempting to bind to ports, indicating the deployment of an unauthorized backdoor listener. |
| **`accept`** / **`accept4`** | `tracepoint/syscalls/sys_enter_accept` | Receiving an incoming connection on a listening socket. | • Incoming connections to processes that should not be accepting traffic. |

---

## 4. Privilege Escalation & Credentials (Privilege Escalation)

These syscalls manipulate process capabilities and identity, often abused to elevate rights or bypass access controls.

| Syscall | Hook / Event Type | Detection Relevance | Security Heuristics |
| :--- | :--- | :--- | :--- |
| **`setuid`** / **`setgid`** / **`setreuid`** | `tracepoint/syscalls/sys_enter_setuid`<br>`lsm/cred_prepare` | Changing user or group identity of the process. | • Sudden transition of a process to UID `0` (root), signaling potential privilege escalation exploits. |
| **`capset`** | `tracepoint/syscalls/sys_enter_capset`<br>`lsm/capset` | Modifying process capabilities. | • Processes granting themselves dangerous capabilities (e.g., `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_RAW`). |

---

## 5. Defense Evasion, Fileless Execution & Injection (Evasion)

Modern threats try to avoid traditional file-based detection by executing in memory, injecting code, or loading malicious kernel extensions.

| Syscall | Hook / Event Type | Detection Relevance | Security Heuristics |
| :--- | :--- | :--- | :--- |
| **`ptrace`** | `tracepoint/syscalls/sys_enter_ptrace`<br>`lsm/ptrace_access_check` | Process tracing and memory reading/writing of other processes. | • Unauthorized processes attempting to attach to target processes (e.g., trying to read memory of authentication agents or sshd to harvest credentials). |
| **`memfd_create`** | `tracepoint/syscalls/sys_enter_memfd_create` | Creating an anonymous file in RAM (does not reside on disk). | • Fileless execution: Creating an anonymous memory fd, writing a payload into it, and executing it using `fexecve`. |
| **`mprotect`** / **`pkey_mprotect`** | `tracepoint/syscalls/sys_enter_mprotect` | Changing protection flags of memory pages. | • Memory pages transitioned to `PROT_WRITE | PROT_EXEC` (Write+Execute), typical of JIT compilers but also shellcode injection. |
| **`bpf`** | `tracepoint/syscalls/sys_enter_bpf`<br>`lsm/bpf` | Interacting with the eBPF subsystem (loading programs, maps). | • Detecting unauthorized or malicious eBPF programs being loaded into the kernel (e.g., eBPF rootkits). |

---

## 6. Critical Security Pattern: Reverse Shell Detection

One of the most valuable alerts in a HIDS is identifying a **reverse shell**. This is detected by observing the redirection of standard file descriptors to network sockets:

1. **`dup`**, **`dup2`**, or **`dup3`** are called where `oldfd` is a socket file descriptor (typically created via `socket` / `connect`) and `newfd` is `0` (stdin), `1` (stdout), or `2` (stderr).
2. When followed by an `execve` of a shell (like `/bin/sh` or `/bin/bash`), this confirms interactive shell control over a socket.
3. **Instrumentation**: Intercept `sys_enter_dup2` / `sys_enter_dup3` and check if the target target file descriptors correspond to a socket family.

---

## 7. eBPF Implementation Strategies & Pitfalls

### Tracepoints vs. LSM vs. Kprobes

* **Syscall Tracepoints (`tracepoint/syscalls/sys_enter_*`)**:
  * **Pros**: Highly stable ABI, portable across kernel versions.
  * **Cons**: Susceptible to **TOCTOU (Time-of-Check to Time-of-Use)** attacks. In user space, arguments passed by reference (like file paths or IP structs) can be modified in user memory *after* eBPF reads them but *before* the kernel processes them.
* **Kprobes/Kretprobes (`kprobe/sys_*`)**:
  * **Pros**: Can inspect any internal kernel function.
  * **Cons**: No stable ABI; kernel function signatures change between minor Linux versions.
* **LSM (Linux Security Module) hooks (`lsm/*`)**:
  * **Pros**: Triggered *inside* the kernel security subsystems after parameters are copied to kernel space (solving the TOCTOU problem). Allows **blocking** of operations (returning `-EACCES`) rather than just monitoring.
  * **Cons**: Requires Linux Kernel 5.7+ and `CONFIG_BPF_LSM` enabled in the kernel config.

### Recommendation
For a robust HIDS:
1. Use **LSM hooks** for file access, credential modifications, and process executions where possible (e.g., `lsm/file_open`, `lsm/bprm_check_security`), as they provide kernel-validated parameters and permit active mitigation.
2. Fall back to **Syscall Tracepoints** for non-blocking telemetry, legacy kernel compatibility, and connection auditing.
