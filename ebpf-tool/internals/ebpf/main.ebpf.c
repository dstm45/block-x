// #include "config.h"
#include "vmlinux.h"
#include <asm-generic/errno-base.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#define in_file
#include "logs.h"
#include "policy.h"


#define PATH_LENGTH 256
#define MAX_ENTRIES 10240
#define PROCESS_LENGTH 64
#define UNDEFINED -600000 //random value

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

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, Policy);
} policy_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} logs_ringbuf SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, Log);
} dummy_log_map SEC(".maps");

struct scratch_t {
    char filename[128];
    char arg0[32];
    char arg1[32];
    char arg2[32];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct scratch_t);
} scratch_map SEC(".maps");


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

SEC("tracepoint/syscalls/sys_enter_socket")
int detect_socket_opening(struct trace_event_raw_sys_enter *ctx) {
    int domain = ctx->args[0];
    if (domain == 2 || domain == 10) { // AF_INET or AF_INET6
        Log *log = (Log*)bpf_ringbuf_reserve(&logs_ringbuf, sizeof(Log), 0);
        if (!log) return 0;
        
        bpf_get_current_comm(log->program, sizeof(log->program));
        
        struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
        struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
        if (parent_task) {
            bpf_probe_read_kernel_str(log->parent_program, sizeof(log->parent_program), &parent_task->comm);
        } else {
            log->parent_program[0] = '\0';
        }
        
        if (domain == 2) {
            bpf_probe_read_kernel_str(log->target, sizeof(log->target), "socket:AF_INET");
        } else {
            bpf_probe_read_kernel_str(log->target, sizeof(log->target), "socket:AF_INET6");
        }
        
        log->syscall = 41; /* __NR_socket */
        bpf_ringbuf_submit(log, 0);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int detect_socket_connect(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr) return 0;
    
    short family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    
    if (family == 2 /* AF_INET */) {
        struct sockaddr_in addr_in = {};
        bpf_probe_read_user(&addr_in, sizeof(addr_in), addr);
        
        Log *log = (Log*)bpf_ringbuf_reserve(&logs_ringbuf, sizeof(Log), 0);
        if (!log) return 0;
        
        bpf_get_current_comm(log->program, sizeof(log->program));
        
        struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
        struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
        if (parent_task) {
            bpf_probe_read_kernel_str(log->parent_program, sizeof(log->parent_program), &parent_task->comm);
        } else {
            log->parent_program[0] = '\0';
        }
        
        unsigned short port = __builtin_bswap16(addr_in.sin_port);
        
        u64 args[1] = { (u64)port };
        bpf_snprintf(log->target, sizeof(log->target), "connect:AF_INET:%d", args, sizeof(args));
        
        log->syscall = 42; /* __NR_connect */
        bpf_ringbuf_submit(log, 0);
    } else if (family == 10 /* AF_INET6 */) {
        struct sockaddr_in6 addr_in6 = {};
        bpf_probe_read_user(&addr_in6, sizeof(addr_in6), addr);
        
        Log *log = (Log*)bpf_ringbuf_reserve(&logs_ringbuf, sizeof(Log), 0);
        if (!log) return 0;
        
        bpf_get_current_comm(log->program, sizeof(log->program));
        
        struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
        struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
        if (parent_task) {
            bpf_probe_read_kernel_str(log->parent_program, sizeof(log->parent_program), &parent_task->comm);
        } else {
            log->parent_program[0] = '\0';
        }
        
        unsigned short port = __builtin_bswap16(addr_in6.sin6_port);
        
        u64 args[1] = { (u64)port };
        bpf_snprintf(log->target, sizeof(log->target), "connect:AF_INET6:%d", args, sizeof(args));
        
        log->syscall = 42; /* __NR_connect */
        bpf_ringbuf_submit(log, 0);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int detect_file_redirection(struct trace_event_raw_sys_enter *ctx) {
    int oldfd = ctx->args[0];
    int newfd = ctx->args[1];
    
    if (newfd >= 0 && newfd <= 2 && oldfd >= 0) {
        struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
        struct files_struct *files = BPF_CORE_READ(current_task, files);
        if (!files) return 0;
        struct fdtable *fdt = BPF_CORE_READ(files, fdt);
        if (!fdt) return 0;
        u32 max_fds = BPF_CORE_READ(fdt, max_fds);
        if ((u32)oldfd < max_fds) {
            struct file **fd_array = BPF_CORE_READ(fdt, fd);
            if (!fd_array) return 0;
            struct file *file = NULL;
            bpf_probe_read_kernel(&file, sizeof(file), fd_array + oldfd);
            if (file) {
                struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
                struct super_block *d_sb = BPF_CORE_READ(dentry, d_sb);
                unsigned long s_magic = BPF_CORE_READ(d_sb, s_magic);
                if (s_magic == 0x534F434B) { // SOCKFS_MAGIC
                    Log *log = (Log*)bpf_ringbuf_reserve(&logs_ringbuf, sizeof(Log), 0);
                    if (!log) return 0;
                    
                    bpf_get_current_comm(log->program, sizeof(log->program));
                    
                    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
                    if (parent_task) {
                        bpf_probe_read_kernel_str(log->parent_program, sizeof(log->parent_program), &parent_task->comm);
                    } else {
                        log->parent_program[0] = '\0';
                    }
                    
                    bpf_probe_read_kernel_str(log->target, sizeof(log->target), "dup2:socket_redirection");
                    
                    log->syscall = 33; /* __NR_dup2 */
                    bpf_ringbuf_submit(log, 0);
                }
            }
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_program_execution(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[0];
    char *const *argv = (char *const *)ctx->args[1];
    
    u32 zero = 0;
    struct scratch_t *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch) return 0;
    
    scratch->filename[0] = '\0';
    scratch->arg0[0] = '\0';
    scratch->arg1[0] = '\0';
    scratch->arg2[0] = '\0';
    
    bpf_probe_read_user_str(scratch->filename, sizeof(scratch->filename), filename);
    
    char *arg_ptr = NULL;
    if (argv) {
        bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[0]);
        if (arg_ptr) {
            bpf_probe_read_user_str(scratch->arg0, sizeof(scratch->arg0), arg_ptr);
        }
        bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[1]);
        if (arg_ptr) {
            bpf_probe_read_user_str(scratch->arg1, sizeof(scratch->arg1), arg_ptr);
        }
        bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[2]);
        if (arg_ptr) {
            bpf_probe_read_user_str(scratch->arg2, sizeof(scratch->arg2), arg_ptr);
        }
    }
    
    Log *log = (Log*)bpf_ringbuf_reserve(&logs_ringbuf, sizeof(Log), 0);
    if (!log) return 0;
    
    bpf_get_current_comm(log->program, sizeof(log->program));
    
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
    if (parent_task) {
        bpf_probe_read_kernel_str(log->parent_program, sizeof(log->parent_program), &parent_task->comm);
    } else {
        log->parent_program[0] = '\0';
    }
    
    u64 args[1] = { (u64)scratch->filename };
    bpf_snprintf(log->target, sizeof(log->target), "exec:%s", args, sizeof(args));
    
    log->syscall = 59; /* __NR_execve */
    bpf_ringbuf_submit(log, 0);
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
