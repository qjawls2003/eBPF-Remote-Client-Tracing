/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Beom Jin An & Abe Melvin */

#ifndef __SSHTRACE_H
#define __SSHTRACE_H
#define ARGSIZE  128
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define INVALID_UID ((uid_t)-1)
#define BASE_EVENT_SIZE (size_t)(&((struct event*)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)


struct data_t {
  pid_t pid;
  uid_t uid;
  pid_t ppid;
  char command[TASK_COMM_LEN];
  int ret;
  struct sockaddr_in6 addr;
  int type_id; // 0:others 1:getpeername 2:getsockname 3:execve
};

struct event {
  pid_t pid;
  pid_t ppid;
  uid_t uid;
  int retval;
  int args_count;
  unsigned int args_size;
  char comm[TASK_COMM_LEN];
  char args[FULL_MAX_ARGS_ARR];
};

#endif /* __SSHTRACE_H */
