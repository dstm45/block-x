#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800 //used to determine ipv4

struct packet_data {
  __be32 destination_ip_address;
  __be32 source_ip_address;
  __u64 packet_size;
}; 

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct packet_data);
} packet_map SEC(".maps");

struct additional_packet_data {
  __u16 dport;
  char process[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct additional_packet_data);
} process_packet SEC(".maps");

SEC("xdp")
int get_packet(struct xdp_md* ctx) {
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void*)(eth+1)> data_end) { 
    return XDP_PASS;
  }
  
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  struct iphdr* ip = (void*)(eth+1);
  if ((void*)(ip+1)> data_end) { 
    return XDP_PASS;
  }
  struct packet_data packet = {
    .destination_ip_address=ip->daddr,
    .source_ip_address=ip->saddr,
    .packet_size=(__u64)(data_end-data)
  };
  __u32 key = 0;
  bpf_map_update_elem(&packet_map, &key, &packet, BPF_ANY); 
  return XDP_DROP;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(get_process_by_packet, struct sock *sk) {
  struct task_struct *tache= (struct task_struct*)bpf_get_current_task();
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  char* process = BPF_CORE_READ(tache, comm);
  __u16 dport = 0;
  bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
  __u32 key = 0;
  struct additional_packet_data data = {};
  bpf_probe_read_kernel(&data.process, sizeof(data.process), &process);
  bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &sk->__sk_common.skc_dport);
  bpf_map_update_elem(&process_packet, &key, &data, BPF_ANY);
  return 0;
}

char LICENSE[] SEC("license") = "GPL"; 
