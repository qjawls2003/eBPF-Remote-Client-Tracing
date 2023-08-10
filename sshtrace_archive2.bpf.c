#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
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
    __type(value, struct data_t);
} sockaddrs SEC(".maps");

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

   int syscall_nr;
   long fd;
   struct sockaddr * upeer_sockaddr; //struct sockaddr *usockaddr;
   int * upeer_addrlen;
};


SEC("tp/syscalls/sys_enter_getpeername")
int tp_sys_enter_getpeername(struct my_syscalls_enter_getpeername *ctx)
{
   
   struct data_t data = {}; 

   //struct sockaddr_in *ip = (struct sockaddr_in *)ctx->usockaddr_ptr;
   //bpf_printk("%ld %s\n", c_ip, "start");
   //int c_ip = bpf_ntohl(&ip->sin_addr.s_addr);
   //bpf_printk("%ld %s\n", ctx->upeer_sockaddr, "start");
   data.client_ip = ctx->upeer_sockaddr;
   //int err = bpf_probe_read_kernel(&data.client_ip, sizeof(data.client_ip), ctx->upeer_sockaddr);
   //if (err != 0) {
   //   bpf_printk("Error");
  // }
   
   bpf_printk("%ld\n", data.client_ip);

   bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_btf_exec_msg);

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_map_update_elem(&sockaddrs, &data.pid, &data, 0);
   //bpf_probe_read(&data.client_ip, sizeof(data.client_ip), &ip->sin_addr.s_addr);

   //bpf_printk("%ld\n", data.client_ip);
   // TODO!! Resolve issues accessing data that isn't aligned to an 8-byte boundary
   // bpf_printk("%s %d\n", tp_btf_exec_msg, pid);
   // bpf_probe_read_kernel_str(&data.command, sizeof(data.command), ctx->pid); 

   //bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
    
   return 0;
}

struct my_syscalls_exit_getpeername {
   unsigned short common_type;
   unsigned char common_flags;
   unsigned char common_preempt_count;
   int common_pid;

   int ret;
};

SEC("tp/syscalls/sys_exit_getpeername")
int tp_sys_exit_getpeername(struct my_syscalls_exit_getpeername *ctx)
{
   
   struct data_t *data;
   struct data_t data2 = {}; 
   u32 pid = bpf_get_current_pid_tgid() >> 32;
	 
    data = bpf_map_lookup_elem(&sockaddrs, &pid);
    if (!data)
		return 0;
    
    
    data2.pid = data->pid;
    data2.uid = data->uid;
   bpf_probe_read_kernel(&data2.message, sizeof(data2.message), tp_btf_exec_msg);
   bpf_get_current_comm(&data2.command, sizeof(data2.command));
    struct sockaddr_in *ip = (struct sockaddr_in *)data->client_ip;
   int err = bpf_probe_read_kernel(&data2.in_client_ip, sizeof(data2.in_client_ip), ip);
   if (err != 0) {
      bpf_printk("Error");
   }   
    bpf_printk("%ld\n", &data2.in_client_ip);

   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data2, sizeof(data2));
    
   return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
