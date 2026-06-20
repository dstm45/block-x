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
  char target[PATH_LENGTH];
  char parent_program[PROGRAM_LENGTH];
} Log;

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
  bpf_ringbuf_submit(log, 0);
}

#endif // !LOGS_H
