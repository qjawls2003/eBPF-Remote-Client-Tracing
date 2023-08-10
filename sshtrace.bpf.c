#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "sshtrace.h"

const char tp_btf_exec_msg[19] = "tp_sys_enter_accept";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct sockaddr_in *);
}  values SEC(".maps");

static int probe_entry(void *ctx, struct sockaddr_in *addr)
{
   __u64 id = bpf_get_current_pid_tgid();
   __u32 pid = id >> 32;
   __u32 tid = (__u32)id;

   bpf_map_update_elem(&values, &tid, &addr, BPF_ANY);
   return 0;
};

static int probe_return(void *ctx, int ret)
{
   __u64 id = bpf_get_current_pid_tgid();
   __u32 pid = id >> 32;
   __u32 tid = (__u32)id;
   __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   struct sockaddr_in **addrpp;
   struct sockaddr_in *addr;
   struct data_t data = {};

   addrpp = bpf_map_lookup_elem(&values, &tid);
   if (!addrpp)
      return 0;

   addr = *addrpp;
   data.pid = pid;
   data.uid = uid;
   data.ret = ret;
   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_probe_read_user(&data.addr, sizeof(data.addr), addr);
   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}


SEC("tp/syscalls/sys_enter_getpeername")
int tp_sys_enter_getpeername(struct trace_event_raw_sys_enter *ctx)
{
   return probe_entry(ctx, (struct sockaddr_in *)ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_getpeername")
int tp_sys_exit_getpeername(struct trace_event_raw_sys_exit *ctx)
{
   return probe_return(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
