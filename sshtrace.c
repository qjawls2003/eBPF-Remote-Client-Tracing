// GNU General Public License
/*
 * Copyright (c) 2023 Beom Jin An & Abe Melvin
 *
 * 2023-09-01 Beom Jin An and Abe Melvin  Created this.
 * sshtrace   Trace execve called from ssh client activity
 */

#define _POSIX_SOURCE
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "sshtrace.h"
#include "log.c/src/log.h"
#include "sshtrace.skel.h"

#define GETPEERNAME 1
#define GETSOCKNAME 2
#define EXECVE 3
#define MAX_ARGS_KEY 259

static int logLevel = LOG_INFO; // set desired logging level here

volatile sig_atomic_t intSignal;

const char *argp_program_version = "sshtrace 0.1";
const char *argp_program_bug_address =
    "https://github.com/qjawls2003/eBPF-Remote-Client-Tracing";
const char argp_program_doc[] =
    "Trace ssh session spawned execve syscall\n"
    "\n"
    "USAGE: sudo ./sshtrace [-a] [-p] [-v] [-w] [-h]\n"

    "EXAMPLES:\n"
    "   ./sshtrace           # trace all ssh-spawned execve syscall\n"
    "   ./sshtrace -a        # trace all execve syscalls\n"
    "   ./sshtrace -p        # printf all logs\n"
    "   ./sshtrace -v        # verbose events\n"
    "   ./sshtrace -w        # verbose warnings\n"
    "   ./sshtrace -h        # show help\n";

static const struct argp_option opts[] = {
    {"all", 'a', NULL, 0, "trace all execve syscall"},
    {"print", 'p', NULL, 0, "printf all logs"},
    {"verbose", 'v', NULL, 0, "verbose debugging"},
    {"warning", 'w', NULL, 0, "verbose warnings"},
    { "max-args", MAX_ARGS_KEY, "MAX_ARGS", 0,
		"max number of arg param logged, defaults to 20" },
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

FILE *fp; // Save logs to File

static struct envVar {
  bool print;
  bool verbose;
  bool warning;
  bool all;
  int max_args;
} envVar = {.print = false, .verbose = false, .warning = false, .all = false,
  .max_args = DEFAULT_MAXARGS
};

void intHandler(int signal) {
  log_trace("Received interrupt signal, exiting");
  intSignal = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {

  if (level >= LIBBPF_DEBUG)
    return 0;

  return vfprintf(stderr, format, args);
}

struct ipData {
  char ipAddress[INET6_ADDRSTRLEN];
  uint16_t port;
};

struct ipData ipHelper(struct sockaddr_in6 *ipRaw) {
  struct ipData ipRes = {0};
  switch (ipRaw->sin6_family) {
  case AF_INET: { // IPv4
    struct sockaddr_in *ip = (struct sockaddr_in *)ipRaw;
    inet_ntop(AF_INET, &(ip->sin_addr), ipRes.ipAddress, INET_ADDRSTRLEN);
    ipRes.port = htons(ip->sin_port);
    log_trace("Converting sockaddr to IPv4 address Successful: %s %d",
              ipRes.ipAddress, ipRes.port);
    return ipRes;
  }
  case AF_INET6: { // IPv6
    struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)ipRaw;
    inet_ntop(AF_INET6, &(ip6->sin6_addr), ipRes.ipAddress, INET6_ADDRSTRLEN);
    ipRes.port = htons(ip6->sin6_port);
    log_trace("Converting sockaddr to IPv6 address Successful: %s %d",
              ipRes.ipAddress, ipRes.port);
    return ipRes;
  }
  default:
    log_trace("Converting sockaddr_in to IP address Not Successful");
    return ipRes;
  }
}

char * print_args(const struct event e)
{
	int i, args_counter = 0;
  char * args = malloc(envVar.max_args);
  args[0] = '\0';
  int len;
	for (i = 0; i < e.args_size && args_counter < e.args_count; i++) {
    len = strlen(args);
		char c = e.args[i];

			if (c == '\0') {
				args_counter++;
				args[len] = ' ';
        args[len+1] = '\0';
        //putchar(' ');
			} else {
				args[len] = c;
        args[len+1] = '\0';
        //putchar(c);
			}
  
	}
  len = strlen(args);
  args[len+1] = '\0';
  //printf("%s\n",args);
  return args;
}

char *getUser(uid_t uid) {
  log_trace("Entering getUser(%d)", uid);
  long bufferSize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufferSize == -1) {
    bufferSize = 16384;
  }
  char *user = (char *)malloc(bufferSize);
  struct passwd *pwd = getpwuid(uid);
  if (pwd == NULL) {
    log_debug("Unable to find username for UID %d", uid);
    char tmp[3] = "n/a";
    strcpy(user, tmp);
  } else {
    strcpy(user, pwd->pw_name);
  }
  log_trace("Exiting getUser(%d) with User: %s", uid, user);
  return user;
}

pid_t getPPID(pid_t pid) {
  log_trace("Entering getPPID(%d)", pid);
  char file[1000] = {0};
  pid_t ppid = 1;
  sprintf(file, "/proc/%d/stat", pid);
  FILE *f = fopen(file, "r");
  if (f == NULL) {
    log_debug("Failed to open %s, returning default PID 1", file);
    return ppid;
  }
  fscanf(f, "%*d %*s %*c %d", &ppid);
  fclose(f);
  log_trace("Exiting getPPID(%d) and returning %d", pid, ppid);
  return ppid;
}

char *getCommand(pid_t pid) {
  log_trace("Entering getCommand(%d)", pid);
  char file[1000] = {0};
  char *comm = (char *)malloc(1000 * sizeof(char));
  sprintf(file, "/proc/%d/stat", pid);
  FILE *f = fopen(file, "r");
  if (f == NULL) {
    log_debug("Failed to open %s, returning empty command", file);
    return comm;
  }
  fscanf(f, "%*d %s %*c %*d", comm);
  fclose(f);
  log_trace("Exiting getCommand(%d) and returning %s", pid, comm);
  return comm;
}

uid_t getUID(pid_t pid) {
  log_trace("Entering getUID(%d)", pid);
  uid_t uid = 0;
  if (pid == 1) {
    log_debug("Attempted getUID() on PID 1, returning %d", uid);
    return uid;
  }
  char file[1000] = {0};
  sprintf(file, "/proc/%d/status", pid);
  FILE *f = fopen(file, "r");
  if (f == NULL) {
    log_debug("Failed to open %s, returning empty UID", file);
    return uid;
  }
  char tmp[256];
  int lines = 9;
  while (lines--) {
    fgets(tmp, 256, f);
  }
  sscanf(tmp, "Uid:\t%d\t", &uid);
  fclose(f);
  log_trace("Exiting getUID(%d) and returning %d", pid, uid);
  return uid;
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
  log_trace("%s", "Entering handle_event()");
  struct data_t *m = data;
  struct ipData sockData = ipHelper(&m->addr);

  // timestamp
  time_t t;
  struct tm *tm;
  char ts[64];
  t = time(NULL);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%c", tm);

  int addrErr;
  int userErr;
  uid_t org_user;
  log_trace("%s", "Getting the user BPF map object");
  int userMap = bpf_obj_get("/sys/fs/bpf/raw_user"); // PID -> user 
  if (userMap <= 0) {
    log_debug("%s", "No file descriptor returned for the user BPF map object");
  } else {
    log_trace("Looking up PPID %d in the user BPF map", m->ppid);
    userErr = bpf_map_lookup_elem(userMap, &m->ppid, &org_user);
  }

  if (userErr == 0) {
    log_trace("Ancestor user found");
  } else {
    log_trace("Ancestor user not found");
  }

  int addrMap = bpf_obj_get("/sys/fs/bpf/addresses"); // pid -> IP data
  if (addrMap <= 0) {
    log_debug("No file descriptor returned for the port BPF map object");
  }
  addrErr = bpf_map_lookup_elem(addrMap, &m->ppid, &sockData);
  if (!addrErr) {
    log_trace("Ancestor sockaddr found (%s) with PID (%d)", m->command,
              m->ppid);
  } else {
    log_trace("Ancestor sockaddr not found (%s) with PID (%d)", m->command,
              m->ppid);
    sockData = ipHelper(&m->addr);
  }

  uint16_t port = 0;
  if (m->type_id == EXECVE) {
    bool sshdFound = false;
    pid_t sshdPID = m->pid;
    pid_t ppid = m->pid;
    char *comm = getCommand(ppid);
    int addrErr = bpf_map_lookup_elem(addrMap, &ppid, &sockData);
    while (ppid > 1 && strncmp(comm, "(sshd)", 6) != 0) {
      free(comm);
      log_trace("Looking up the parent process of %d", ppid);
      pid_t ancestorPID = getPPID(ppid);
      log_trace("Found parent process of %d, ancestor is %d", ppid,
                ancestorPID);
      log_trace("Looking up the command used to invoke PID %d", ancestorPID);
      char *comm = getCommand(ancestorPID);
      log_trace("Found invoking command of %d, %s", ancestorPID, comm);
      if (strncmp(comm, "(sshd)", 6) == 0) {
        log_trace("Found an sshd task in the process tree with PID: %d and "
                  "command: %s",
                  ancestorPID, comm);
        sshdFound = true;
        // We want the process just before sshd, i.e. ppid
        sshdPID = ppid;
        log_trace("Looking up PID %d in the sockaddr BPF map", sshdPID);
        userErr = bpf_map_lookup_elem(userMap, &sshdPID,
                                      &org_user); // look up org_user
        addrErr = bpf_map_lookup_elem(addrMap, &sshdPID,
                                      &sockData); // look up IP data
        if (addrErr != 0) {
          log_trace(
              "Couldn't find a corresponding sockaddr_in for the sshd process");
        } else {
          log_trace("Found a corresponding sockaddr_in for the sshd process");
          break;
        }
      }
      ppid = ancestorPID;
    }

    if (addrMap) {
      bpf_map_update_elem(addrMap, &m->pid, &sockData, BPF_ANY);
    }

    free(comm);
    if (sshdFound == false && !envVar.all) {
      close(addrErr);
      close(userMap);
      return;
    }
    log_trace("Reporting %d as the originating PID and found: %d", sshdPID,
              addrErr);
    log_trace("Converting sockaddr_in to presentable IP address at %s",
              sockData.ipAddress);

    char *originalUser;
    if (userErr == 0) {
      originalUser = getUser(org_user);
      log_trace("OriginalUser found, %s", originalUser);
    } else { // case when localhost ssh to localhost
      uid_t originalUID = getUID(sshdPID);
      originalUser = getUser(originalUID);
      log_trace("OriginalUser not found, use currentUser, %s", originalUser);
    }
    char *currentUser = getUser(m->uid);
    struct event eventArg;
    int eventErr;
    int eventMap = bpf_obj_get("/sys/fs/bpf/execs"); // event for binary path
    if (eventMap <= 0) {
      log_trace("%s",
                "No file descriptor returned for the user BPF map object");
    } else {
      eventErr = bpf_map_lookup_elem(eventMap, &m->pid, &eventArg);
      if (eventErr == 0) {
        log_trace("Looked up ARGs '%d' in the event BPF map", eventArg.pid);
      } else {
        log_trace("No Event returned for %d, instead got: %d", m->pid,
                  eventArg.pid);
      }
    }
    char *args_log = print_args(eventArg);
    if (fp == NULL) {
        log_info("Log file could not be opened");
    }
    fprintf(fp,
            "{\"timestamp\":%ld,\"pid\":%d,\"ppid\":%d,\"uid\":%d,"
            "\"currentUser\":\"%s\",\"originalUser\":\"%s\",\"command\":\"%s\","
            "\"ip\":\"%s\",\"port\":%d,\"commargs\":\"%s\"}\n",
            t, m->pid, m->ppid, m->uid, currentUser, originalUser, m->command,
            sockData.ipAddress, sockData.port, args_log);
    fflush(fp);
    if (envVar.print) {
      printf("%-8s %-6d %-6d %-6d %-16s %-16s %-16s %-16s %-16d %-6s\n", ts,
             m->pid, m->ppid, m->uid, currentUser, originalUser, m->command,
             sockData.ipAddress, sockData.port, args_log);
    }
    //free(currentUser);
    //free(originalUser);
    free(args_log);

  } else if (m->type_id == GETPEERNAME) {
    struct ipData ipRes = ipHelper(&m->addr);

    if (addrMap) {
      bpf_map_update_elem(addrMap, &m->pid, &ipRes, BPF_ANY);
    }

    log_trace("Converting sockaddr to IP address succeeded: %s for PID: %d",
              ipRes.ipAddress, m->pid);
    if (!strncmp(ipRes.ipAddress, "127.0.0.1", INET_ADDRSTRLEN) ||
        !strncmp(ipRes.ipAddress, "::1", INET6_ADDRSTRLEN)) {
      log_trace("Client IP address is localhost");
      struct ipData tmpSockData;
      uid_t originalUser;
      log_trace("Getting the port BPF map object");
      int portMap = bpf_obj_get("/sys/fs/bpf/raw_port"); // BASH port -> IP
                                                         // #Map2
      if (portMap <= 0) {
        log_debug("No file descriptor returned for the port BPF map object");
      }
      log_trace("Getting the userport BPF map object");
      int userportMap =
          bpf_obj_get("/sys/fs/bpf/raw_userport"); // BASH port -> IP #Map2
      if (userportMap <= 0) {
        log_debug(
            "No file descriptor returned for the userport BPF map object");
      }
      if (portMap && userportMap) {
        log_trace("Looking up the sockaddr_in corresponding to port %d in the "
                  "port map",
                  port);
        // look up port to get original IP data
        bpf_map_lookup_elem(portMap, &ipRes.port, &tmpSockData);
        // look up port to get original user
        bpf_map_lookup_elem(userportMap, &ipRes.port, &originalUser);
        // update PID with original user
        bpf_map_update_elem(userMap, &m->pid, &originalUser, BPF_ANY);
        // update PID with the original ssh IP data
        bpf_map_update_elem(addrMap, &m->pid, &tmpSockData, BPF_ANY);
      }
      //close(portMap);
      //close(userportMap);
    }

  } else if (m->type_id == GETSOCKNAME) {
    struct ipData ipRes = ipHelper(&m->addr); // must be m->addr

    log_trace("Converting sockaddr to IP address succeeded: %s",
              ipRes.ipAddress);
    if (!strncmp(ipRes.ipAddress, "127.0.0.1", INET_ADDRSTRLEN) ||
        !strncmp(ipRes.ipAddress, "::1", INET6_ADDRSTRLEN)) {
      log_trace("Your IP address is localhost");
      int map_port =
          bpf_obj_get("/sys/fs/bpf/raw_port"); // BASH port -> IP #Map2
      int userMapport =
          bpf_obj_get("/sys/fs/bpf/raw_userport"); // BASH port -> IP #Map2
      if (userErr) {
        org_user = m->uid;
      }
      if (map_port && userMapport) {
        int sockDataErr = bpf_map_lookup_elem(addrMap, &m->ppid, &sockData);
        if (sockDataErr == 0) {
          if (sockData.port == 0) {
            sockData = ipRes;
          }
          log_trace("Found sockaddr_in for PID %d with IP: %s", m->ppid,
                    sockData.ipAddress);
        } else {
          log_trace("Could not find sockaddr_in for PID %d", m->ppid);
          sockData = ipRes;
        }
        bpf_map_update_elem(
            map_port, &ipRes.port, &sockData,
            BPF_ANY); // update Map2 with Port -> ip (sockaddr_in)
        log_trace("Updating the UID %d corresponding to port %d Command: %s",
                  org_user, ipRes.port, m->command);
        bpf_map_update_elem(userMapport, &ipRes.port, &org_user,
                            BPF_ANY); // update Map3 with Port -> org_user
      } else {
        log_debug("Port maps file decriptors not found");
      }

      //close(userMapport);
      //close(map_port);
    }
  } else {
    // no events passed here
    printf("Unexpected events sent");
  }

  // close(sockaddrMap);
  //close(userMap);
  log_trace("Exiting handle_event()");
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz) {
  printf("lost event\n");
}

static int parse_arg(int key, char *arg, struct argp_state *state) {
  long int max_args;
  switch (key) {
  case 'p':
    envVar.print = true;
    break;
  case 'v':
    envVar.verbose = true;
    logLevel = LOG_TRACE;
    break;
  case 'a':
    envVar.all = true;
    break;
  case 'w':
    envVar.warning = true;
    logLevel = LOG_DEBUG;
    break;
  case 'h':
    argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
    break;
  case MAX_ARGS_KEY:
		errno = 0;
		max_args = strtol(arg, NULL, 10);
		if (errno || max_args < 1 || max_args > TOTAL_MAX_ARGS) {
			fprintf(stderr, "Invalid MAX_ARGS %s, should be in [1, %d] range\n",
					arg, TOTAL_MAX_ARGS);

			argp_usage(state);
		}
		envVar.max_args = max_args;
		break;
  }
  return 0;
}



int main(int argc, char **argv) {

  static const struct argp argp = {
      .options = opts,
      .parser = parse_arg,
      .doc = argp_program_doc,
  };
  int argErr = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (argErr)
    return argErr;
  log_info("%s", "Starting program...");
  log_set_level(logLevel);
  if (envVar.print) {
    printf("%-24s %-6s %-6s %-6s %-16s %-16s %-16s %-16s %-16s %-6s\n",
           "Timestamp", "PID", "PPID", "UID", "Current User", "Origin User",
           "Command", "IP Address", "Port", "Command Args");
  }

  fp = fopen("/var/log/sshtrace.log", "a"); // open file
  if (fp == NULL) {
    log_info("Log file could not be created or opened");
    return -1;
  }
  log_trace("%s", "Setting LIBBPF options");
  libbpf_set_print(libbpf_print_fn);
  char log_buf[128 * 1024];
  LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_buf = log_buf,
              .kernel_log_size = sizeof(log_buf), .kernel_log_level = 1, );

  log_trace("%s", "Opening BPF skeleton object");
  struct sshtrace_bpf *skel = sshtrace_bpf__open_opts(&opts);
  if (!skel) {
    log_trace("%s", "Error while opening BPF skeleton object");
    return EXIT_FAILURE;
  }

  int err = 0;

  log_trace("%s", "Loading BPF skeleton object");
  err = sshtrace_bpf__load(skel);
  // Print the verifier log
  /*
        for (int i=0; i < 10000; i++) {
                if (log_buf[i] == 0 && log_buf[i+1] == 0) {
                        break;
                }
                printf("%c", log_buf[i]);
        }
  */
  if (err) {
    log_trace("%s", "Error while loading BPF skeleton object");
    goto cleanup;
  }

  log_trace("%s", "Attaching BPF skeleton object");
  err = sshtrace_bpf__attach(skel);
  if (err) {
    log_trace("%s", "Error while attaching BPF skeleton object");
    goto cleanup;
  }

  log_trace("%s", "Initializing perf buffer");
  struct perf_buffer *pb = perf_buffer__new(
      bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
  if (!pb) {
    log_trace("%s", "Error while initializing perf buffer");
    goto cleanup;
  }

  log_trace("Setting up interrupt signal handler");
  signal(SIGINT, intHandler);

  log_trace("%s", "Start polling for BPF events...");
  while (!intSignal) {
    err = perf_buffer__poll(pb, 100 /* timeout, ms */);
  }

  log_trace("%s", "Freeing perf buffer");
  perf_buffer__free(pb);
  goto cleanup;

cleanup:
  log_trace("%s", "Closing File");
  fclose(fp);
  log_trace("%s", "Entering cleanup");
  sshtrace_bpf__destroy(skel);
  log_trace("%s", "Finished cleanup");

  return EXIT_SUCCESS;
}
