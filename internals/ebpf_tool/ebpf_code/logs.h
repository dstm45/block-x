#ifndef LOGS_H
#define LOGS_H

#ifndef in_file
#include <stddef.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>
#endif

#define PROGRAM_LENGTH 256
#define PATH_LENGTH 256

typedef struct Log {
  char program[PROGRAM_LENGTH];
  uint32_t syscall; 
  /**
   * The resource/action target. To be compatible with N-gram scoring/anomaly
   * detection models, this string MUST be formatted in a normalized, low-cardinality
   * style to prevent vocabulary explosion:
   *   - socket: socket:AF_INET or socket:AF_INET6 (static family category)
   *   - connect: connect:AF_INET:<port> or connect:AF_INET6:<port> (removes dynamic IP, keeps service port)
   *   - dup2: dup2:socket_redirection (removes dynamic file descriptors)
   *   - execve: exec:<binary_path> (removes dynamic command arguments)
   */
  char target[PATH_LENGTH];
  char parent_program[PROGRAM_LENGTH];
  uint32_t pid;
  uint32_t ppid;
  uint32_t uid;
  uint32_t gid;
} Log;

#define POPULATE_LOG_METADATA(log) \
    do { \
        u64 __pid_tgid = bpf_get_current_pid_tgid(); \
        (log)->pid = __pid_tgid >> 32; \
        (log)->uid = bpf_get_current_uid_gid(); \
        (log)->gid = bpf_get_current_uid_gid() >> 32; \
        struct task_struct *__curr = (struct task_struct *)bpf_get_current_task(); \
        struct task_struct *__parent = BPF_CORE_READ(__curr, real_parent); \
        (log)->ppid = __parent ? BPF_CORE_READ(__parent, tgid) : 0; \
    } while (0)


// 1. Replaced __builtin_memcpy with bpf_probe_read_kernel to bypass Clang limits
// 2. Added the missing assignment for the syscall
static __inline void fill_logs(Log *log, const char *program, const char *target, const char *parent_program, uint32_t syscall) {
  if (!log) return;

  bpf_probe_read_kernel_str(&log->program, sizeof(log->program), program);
  bpf_probe_read_kernel_str(&log->target, sizeof(log->target), target);
  bpf_probe_read_kernel_str(&log->parent_program, sizeof(log->parent_program), parent_program);
  
  log->syscall = syscall; // Assign the value directly
}

// 3. Passed the ringbuf map pointer as a parameter so this header is perfectly modular
static __inline void emit_logs(void *ringbuf_map, const char *program, const char *target, const char *parent_program, uint32_t syscall) {
  Log *log = (Log*)bpf_ringbuf_reserve(ringbuf_map, sizeof(Log), 0);
  if (!log) return;

  fill_logs(log, program, target, parent_program, syscall);
  POPULATE_LOG_METADATA(log);
  bpf_ringbuf_submit(log, 0);
}

#endif // LOGS_H
