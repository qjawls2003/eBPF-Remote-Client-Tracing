#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sshtrace.h"

const char tp_btf_exec_msg[16] = "tp_getpeername";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct msg_t);
} my_config SEC(".maps");

struct my_syscalls_enter_getpeername {
   unsigned short common_type;
   unsigned char common_flags;
   unsigned char common_preempt_count;
   int common_pid;

   long syscall_nr;
   long fd;
   void *sockaddr_ptr; //struct sockaddr *usockaddr;
   long usockaddr_len;
};

SEC("tp/syscalls/sys_enter_getpeername")
int tp_sys_enter_getpeername(struct my_syscalls_enter_getpeername *ctx)
{
   struct data_t data = {}; 
   // pid_t pid = ctx->pid; 
   bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_btf_exec_msg);
   //bpf_probe_read_kernel(&data.sockaddr, sizeof(data.sockaddr), &ctx->sockaddr_ptr);

   //bpf_probe_read_user_str(&data.sa_data, sizeof(data.sa_data), ctx->sockaddr_ptr->sa_data);
   //bpf_probe_read_user_str(&data.addr, sizeof(data.addr), ctx->);
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   bpf_get_current_comm(&data.command, sizeof(data.command));

   // TODO!! Resolve issues accessing data that isn't aligned to an 8-byte boundary
   // bpf_printk("%s %d\n", tp_btf_exec_msg, pid);
   // bpf_probe_read_kernel_str(&data.command, sizeof(data.command), ctx->pid); 

   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
