// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Copyright (c) 2023 Beom Jin An & Abe Melvin
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <string.h>
#include "sshtrace.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct sockaddr_in6 *);
} values SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct ipData);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} addresses SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct event);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} execs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct sockaddr_in6 *);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} raw_sockaddr SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, uint16_t);
  __type(value, struct ipData);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} raw_port SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, uid_t);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} raw_user SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, uint16_t);
  __type(value, uid_t);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} raw_userport SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct ipData {
  char ipAddress[46];
  uint16_t port;
};

static int probe_entry_getpeername(void *ctx, struct sockaddr_in6 *addr) {
  __u64 id = bpf_get_current_pid_tgid();
  pid_t pid = id >> 32;
  //pid_t tid = (__u32)id;

  bpf_map_update_elem(&values, &pid, &addr, BPF_ANY);
  return 0;
};

static int probe_return_getpeername(void *ctx, int ret) {
  __u64 id = bpf_get_current_pid_tgid();
  pid_t pid = id >> 32;
  //pid_t tid = (__u32)id;
  uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  struct sockaddr_in6 **addrpp;

  addrpp = bpf_map_lookup_elem(&values, &pid);
  if (!addrpp)
    return 0;

  struct sockaddr_in6 *addr;
  addr = *addrpp;

  struct data_t data = {};
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  data.ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
  data.pid = pid;
  data.uid = uid;
  data.ret = ret;
  bpf_get_current_comm(&data.command, sizeof(data.command));
  data.type_id = 1;
  bpf_probe_read_user(&data.addr, sizeof(data.addr), addr);
  //bpf_map_update_elem(&raw_sockaddr, &pid, &data.addr, BPF_ANY);

  int res = bpf_strncmp(data.command, 8, "sshd");
  if (!res) {
    bpf_map_update_elem(&raw_sockaddr, &pid, &data.addr, BPF_ANY);
    bpf_map_update_elem(&raw_user, &pid, &data.uid, BPF_ANY);
    //bpf_printk("Updating: %d IP: %d", pid);
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
  }

  return 0;
}

static int probe_entry_getsockname(void *ctx, struct sockaddr_in6 *addr) {
  __u64 id = bpf_get_current_pid_tgid();
  pid_t pid = id >> 32;
  //pid_t tid = (__u32)id;

  bpf_map_update_elem(&values, &pid, &addr, BPF_ANY);
  return 0;
};

static int probe_return_getsockname(void *ctx, int ret) {
  __u64 id = bpf_get_current_pid_tgid();
  pid_t pid = id >> 32;
  //pid_t tid = (__u32)id;
  uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  //struct sockaddr_in **addrpp;
  //struct sockaddr_in *addr;
  struct sockaddr_in6 **addrpp;
  struct sockaddr_in6 *addr;
  struct data_t data = {};

  addrpp = bpf_map_lookup_elem(&values, &pid);
  if (!addrpp)
    return 0;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  data.ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);

  addr = *addrpp;
  data.pid = pid;
  data.uid = uid;
  data.ret = ret;
  bpf_get_current_comm(&data.command, sizeof(data.command));
  data.type_id = 2;
  bpf_probe_read_user(&data.addr, sizeof(data.addr), addr);
  int res = bpf_strncmp(data.command, 8, "ssh");
  if (!res) {
    // bpf_printk("Command: %s , %s Res: %d",str1, data.command, res);
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
  }

  return 0;
}

SEC("tp/syscalls/sys_enter_getpeername")
int tp_sys_enter_getpeername(struct trace_event_raw_sys_enter *ctx) {
  //return probe_entry_getpeername(ctx, (struct sockaddr_in *)ctx->args[1]);
  return probe_entry_getpeername(ctx, (struct sockaddr_in6*)ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_getpeername")
int tp_sys_exit_getpeername(struct trace_event_raw_sys_exit *ctx) {
  return probe_return_getpeername(ctx, (int)ctx->ret);
}

SEC("tp/syscalls/sys_enter_getsockname")
int tp_sys_enter_getsockname(struct trace_event_raw_sys_enter *ctx) {
  //return probe_entry_getsockname(ctx, (struct sockaddr_in *)ctx->args[1]);
  return probe_entry_getsockname(ctx, (struct sockaddr_in6*)ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_getsockname")
int tp_sys_exit_getsockname(struct trace_event_raw_sys_exit *ctx) {
  return probe_return_getsockname(ctx, (int)ctx->ret);
}

const volatile bool filter_cg = false;
const volatile bool ignore_failed = true;
const volatile uid_t targ_uid = INVALID_UID;
const volatile int max_args = DEFAULT_MAXARGS;
static const struct event empty_event = {};

static __always_inline bool valid_uid(uid_t uid) { return uid != INVALID_UID; }

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(
    struct trace_event_raw_sys_enter *ctx) {
  u64 id;
  pid_t pid, tgid;
  unsigned int ret;
  struct event *event;
  struct task_struct *task;
  const char **args = (const char **)(ctx->args[1]);
  const char *argp;
  int i;
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
    return 0;

  uid_t uid = (u32)bpf_get_current_uid_gid();
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
  task = (struct task_struct *)bpf_get_current_task();
  event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
      

  event->args_count = 0;
  event->args_size = 0;
  
  ret = bpf_probe_read_user_str(event->args, ARGSIZE, (const char *)ctx->args[0]);
  
  if (ret <= ARGSIZE) {
    event->args_size += ret;
  } else {
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
  //bpf_printk("Event...arg count: %d, arg: %s", event->args_count, event->args);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(
    struct trace_event_raw_sys_exit *ctx) {

  __u64 id = bpf_get_current_pid_tgid();
  //pid_t pid = id >> 32;
  pid_t tid = (__u32)id;

  int ret;
  struct task_struct *task;
  pid_t ppid;


  struct data_t data = {}; // copy
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
    return 0;

  u32 uid = (u32)bpf_get_current_uid_gid();

  if (valid_uid(targ_uid) && targ_uid != uid)
    return 0;

  ret = ctx->ret;
  if (ignore_failed && ret < 0)
    goto cleanup;

  task = (struct task_struct *)bpf_get_current_task();
  ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
  // make data_t event
  data.pid = tid;
  data.uid = uid;
  data.ret = ret;
  data.ppid = ppid;
  data.type_id = 3;
  bpf_get_current_comm(&data.command, sizeof(data.command));

  // size_t len = EVENT_SIZE(e);
  // if (len <= sizeof(e))
  //bpf_printk("Sending event...");

  bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));

cleanup:
  //bpf_map_delete_elem(&execs, &pid);
  return 0;
}


