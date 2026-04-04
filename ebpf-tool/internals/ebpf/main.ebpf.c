// #include "config.h"
#include "vmlinux.h"
#include <asm-generic/errno-base.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PATH_LENGTH 256
#define MAX_ENTRIES 10240
#define PROCESS_LENGTH 64
#define UNDEFINED -645

struct data_t {
  char process_name[PROCESS_LENGTH];
  char filepath[PATH_LENGTH];
  u32 uid;
  u32 pid;
  u32 gid;
  u32 parent_pid;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct data_t);
} datatable SEC(".maps");


char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_openat")
int detect_file_opening(struct trace_event_raw_sys_enter *ctx) {
  struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
  struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
  struct tty_struct *tty = BPF_CORE_READ(parent_task, signal, tty);
  u32 parent_pid = UNDEFINED;
  u32 parent_tgid = UNDEFINED;
  if (parent_task != NULL) {
    parent_pid = BPF_CORE_READ(parent_task, pid);
    parent_tgid = BPF_CORE_READ(parent_task, tgid);
  }
  struct data_t data = {};
  bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
  data.uid = (u32)bpf_get_current_uid_gid();
  data.pid = BPF_CORE_READ(current_task, pid);
  data.parent_pid = parent_pid;
  data.gid = bpf_get_current_uid_gid() >> 32;
  bpf_probe_read_user_str(data.filepath, sizeof(data.filepath), (const char *)ctx->args[1]);
  bpf_map_update_elem(&datatable, &data.pid, &data, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int check_if_file_exists(struct trace_event_raw_sys_exit *ctx) {
  struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  if (ctx->ret >= 0) {
    return 0;
  } else {
    bpf_map_delete_elem(&datatable, &pid);
  }
  return 0;
}

SEC("lsm/file_open")
int BPF_PROG(get_path, struct file *file, int mask) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct data_t *data = (struct data_t *)bpf_map_lookup_elem(&datatable, &pid);
  if (data == NULL) { 
    return 0;
  }
  if (bpf_d_path((struct path *)&file->f_path, data->filepath, sizeof(data->filepath)) < 0) {
    return 0;
  }
  return 0;
}
