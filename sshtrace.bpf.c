#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <string.h>
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
    __type(key, pid_t);
    __type(value, struct sockaddr_in *);
}  values SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct event);
} execs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct sockaddr_in *);
}  raw_sockaddr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

static int probe_entry(void *ctx, struct sockaddr_in *addr)
{
   __u64 id = bpf_get_current_pid_tgid();
   //__u32 pid = id >> 32;
   pid_t tid = (__u32)id;

   bpf_map_update_elem(&values, &tid, &addr, BPF_ANY);
   return 0;
};

static int probe_return(void *ctx, int ret)
{
   __u64 id = bpf_get_current_pid_tgid();
   pid_t pid = id >> 32;
   pid_t tid = (__u32)id;
   uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
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
   bpf_map_update_elem(&raw_sockaddr, &pid, &data.addr, BPF_ANY);
  
   bpf_printk("PPID getpeername_exit map: %d", addr);
   //bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
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


const volatile bool filter_cg = false;
const volatile bool ignore_failed = true;
const volatile uid_t targ_uid = INVALID_UID;
const volatile int max_args = DEFAULT_MAXARGS;

static const struct event empty_event = {};


static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	u64 id;
	pid_t pid, tgid;
	unsigned int ret;
	struct event *event;
	struct task_struct *task;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;

   if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	uid_t uid = (u32)bpf_get_current_uid_gid();
	int i;
   if (valid_uid(targ_uid) && targ_uid != uid)
		return 0;
	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;
	if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
		return 0;

	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	event->pid = tgid;
	event->uid = uid;
	task = (struct task_struct*)bpf_get_current_task();
	event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
	event->args_count = 0;
	event->args_size = 0;

	ret = bpf_probe_read_user_str(event->args, ARGSIZE, (const char*)ctx->args[0]);
	if (ret <= ARGSIZE) {
		event->args_size += ret;
	} else {
		/* write an empty string */
		event->args[0] = '\0';
		event->args_size++;
	}

	event->args_count++;
	#pragma unroll
	for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
		bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
		if (!argp)
			return 0;

		if (event->args_size > LAST_ARG)
			return 0;

		ret = bpf_probe_read_user_str(&event->args[event->args_size], ARGSIZE, argp);
		if (ret > ARGSIZE)
			return 0;

		event->args_count++;
		event->args_size += ret;
	}
	/* try to read one more argument to check if there is one */
	bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
	if (!argp)
		return 0;

	/* pointer to max_args+1 isn't null, asume we have more arguments */
	event->args_count++;
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
   pid_t pid = id >> 32;
   pid_t tid = (__u32)id;
	int ret;
  	struct task_struct *task;
   //struct sockaddr_in **addrpp;
   struct sockaddr_in *addr;
   pid_t ppid;
	//struct event *event;
   struct data_t data = {}; //copy
   if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	u32 uid = (u32)bpf_get_current_uid_gid();

	if (valid_uid(targ_uid) && targ_uid != uid)
		return 0;
   
	//event = bpf_map_lookup_elem(&execs, &pid);
	//if (!event)
	//	return 0;
	ret = ctx->ret;
	if (ignore_failed && ret < 0)
		goto cleanup;

	//event->retval = ret;
//IP address
  
   task = (struct task_struct*)bpf_get_current_task();
   ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
   addr = bpf_map_lookup_elem(&raw_sockaddr, &ppid);

   bpf_printk("PPID execv map: %d", addr);
   //if (!addr)
   //   return 0;
   //e.pid = event->pid;

   //e.ppid = event->ppid;
   //e.uid = event->uid;
   //e.retval = event->retval;
   //e.args_count = event->args_count;
   //e.args_size = event->args_size;
   //bpf_probe_read_user(&e.comm,sizeof(e.comm), event->comm);
   //bpf_probe_read_user(&e.args,sizeof(e.args), event->args);
   //addr = *addrpp;

   data.pid = tid;
   data.uid = uid;
   data.ret = ret;
   data.ppid = ppid;
   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_probe_read_user(&data.addr, sizeof(data.addr), addr);


	//size_t len = EVENT_SIZE(e);
	//if (len <= sizeof(e))
	bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));

cleanup:
	bpf_map_delete_elem(&execs, &pid);
	return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
