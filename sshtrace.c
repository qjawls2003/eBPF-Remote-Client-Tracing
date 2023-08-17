#define _POSIX_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include "sshtrace.h"
#include "sshtrace.skel.h"
#include "log.c/src/log.h"
#include "logger.h"

#define GETPEERNAME 1
#define GETSOCKNAME 2
#define EXECVE 3

volatile sig_atomic_t intSignal;

void intHandler(int signal) {
  log_trace("Received interrupt signal, exiting");
  intSignal = 1;
}

void logger(const char *tag, const char *message) {
  time_t now;
  time(&now);
  printf("%s [%s]: %s\n", ctime(&now), tag, message);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {

  if (level >= LIBBPF_DEBUG)
    return 0;

  return vfprintf(stderr, format, args);
}

char *getUser(uid_t uid) {
  log_trace("Entering getUser()");
  if (uid == 0) {
    log_trace("UID was 0, returning root");
    char root[4] = "root";
    char *ptr = root;
    return ptr;
  }
  log_trace("Setting buffer size according to SYSCONF");
  long bufferSize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufferSize == -1) //Value was indeterminate 
    bufferSize = 16384; // Should be more than enough 
   /*
   log_trace("Allocating memory for buffer: %d", bufferSize);
   char *buf = malloc(bufferSize);
   if (buf == NULL) {
  	log_error("Failed to allocate memory for buffer: %d", bufferSize);
  	exit(EXIT_FAILURE);
   }
   */
  
  struct passwd pwd;
  struct passwd *result;
  char buf[bufferSize];
  log_trace("Calling getpwuid_r() to retrieve the readable username for %d", uid);
  int s = getpwuid_r(uid, &pwd, buf, bufferSize, &result);
  if (result == NULL) {
    if (s == 0) {
      log_info("Unable to find username for UID %d", uid);
    } else {
		errno = s;
      log_error("Encountered an error while calling getpwuid_r()");
    }
    exit(EXIT_FAILURE);
  }
   //log_trace("Freeing the memory allocated for buffer");
   //free(buf);
  log_debug("Exiting getUser() with User: %s", pwd.pw_name);
  return pwd.pw_name;
}



pid_t getPPID(pid_t pid) {
  log_trace("Entering getPPID(%d)", pid);
  char file[1000] = {0};
  pid_t ppid = 1;
  sprintf(file, "/proc/%d/stat", pid);
  FILE *f = fopen(file, "r");
  if (f == NULL) {
    log_error("Failed to open %s, returning default PID 1", file);
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
    log_error("Failed to open %s, returning empty command", file);
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
    log_error("Failed to open %s, returning empty UID", file);
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
  struct sockaddr_in ip;
  char ipAddress[INET_ADDRSTRLEN] = {0};

  pid_t ppid = m->ppid;
  int sockaddrErr = 0;
  log_trace("Getting the sockaddr BPF map object");
  int sockaddrMap =
      bpf_obj_get("/sys/fs/bpf/raw_sockaddr"); // BASH PID -> IP #Map1
  if (sockaddrMap <= 0) {
    log_trace("No file descriptor returned for the sockaddr BPF map object");
  }
  sockaddrErr = bpf_map_lookup_elem(sockaddrMap, &ppid, &ip);
  if (!sockaddrErr) {
    log_trace("Ancestor sockaddr found");
  } else {
    log_trace("Ancestor sockaddr not found");
  }
  /*else {
    while (ppid > 0 && sockaddrErr) {
      log_trace("Looking up PPID %d in the sockaddr BPF map", ppid);
      sockaddrErr = bpf_map_lookup_elem(sockaddrMap, &ppid, &ip);
      log_trace("Looking up the parent process of %d", ppid);
      pid_t ancestorPID = getPPID(ppid);
      ppid = ancestorPID;
      // err = bpf_map_lookup_elem(map_pid, &ppid, &ip);
    }
    log_trace("Oldest ancestor PID found: %d", ppid);
  }

  if (!sockaddrErr) {
    log_trace("Ancestor sockaddr found");
  } else {
    log_trace("Ancestor sockaddr not found");
  }

  */
  int userErr;
  uid_t org_user;
  log_trace("%s", "Getting the user BPF map object");
  int userMap = bpf_obj_get("/sys/fs/bpf/raw_user"); // BASH PID -> user #Map3
  if (userMap <= 0) {
    log_trace("%s", "No file descriptor returned for the user BPF map object");
  } else {
    log_trace("Looking up PPID %d in the user BPF map", m->ppid);
    userErr = bpf_map_lookup_elem(userMap, &m->ppid, &org_user);
  }

  if (userErr == 0) {
    log_trace("Ancestor user found");
  } else {
    log_trace("Ancestor user not found");
  }

  uint16_t port = 0;
  if (m->type_id == EXECVE) {
    bool sshdFound = false;
    pid_t sshdPID = m->pid;
    pid_t ppid = m->pid;
    char *comm = getCommand(ppid);
    int sockaddrErr = bpf_map_lookup_elem(sockaddrMap, &ppid, &ip);
    while (ppid > 1 && strncmp(comm, "(sshd)", 6) != 0) {
      free(comm);
      log_trace("Looking up the parent process of %d", ppid);
      pid_t ancestorPID = getPPID(ppid);
      log_trace("Found parent process of %d, ancestor is %d", ppid, ancestorPID);
      log_trace("Looking up the command used to invoke PID %d", ancestorPID);
      char *comm = getCommand(ancestorPID);
      log_trace("Found invoking command of %d, %s", ancestorPID, comm);
      if (strncmp(comm, "(sshd)", 6) == 0) {
        log_trace("Found an sshd task in the process tree with PID %d", ancestorPID);
        sshdFound = true;
        // We want the process just before sshd, i.e. ppid
        sshdPID = ppid;
        log_trace("Looking up PID %d in the sockaddr BPF map", sshdPID);
        sockaddrErr = bpf_map_lookup_elem(sockaddrMap, &sshdPID, &ip);
        if (sockaddrErr != 0) {
          log_trace("Couldn't find a corresponding sockaddr_in for the sshd process");
        } else {
          log_trace("Found a corresponding sockaddr_in for the sshd process");
          break;
        }
      }
      ppid = ancestorPID;
    }
    log_trace("Reporting %d as the originating PID", sshdPID);
    free(comm);
    if (sshdFound == false) {
      return;
    }

    log_trace("Converting sockaddr_in to presentable IP address");
    inet_ntop(AF_INET, &(ip.sin_addr), ipAddress, INET_ADDRSTRLEN);
    log_trace("Converting sockaddr_in to IP address succeeded");
    log_trace("Converting port to presentable format");
    port = htons(ip.sin_port);
    log_trace("Converting port succeeded");

    // inet_ntop(AF_INET, &(m->addr.sin_addr), ipAddress, INET_ADDRSTRLEN);
    // port = htons(m->addr.sin_port);

    // printf("%-6d %-6d %-6d %-16s %-16s %-16s %16s %d\n", m->pid, m->ppid,
    // m->uid, user_c, user_org, m->command, ipAddress, port);
    //uid_t userAncestor = getUID(org_user);
	char* currentUser = getUser(m->uid);
	char * originalUser;
	if (!userErr) {
			originalUser = getUser(org_user);
		} else {
			originalUser = currentUser;
		}
	
	printf("%d %d \n",m->uid,org_user);
    printf("%-6d %-6d %-6d %-16s %-16s %-16s %-16s %-16d\n", m->pid, m->ppid,
           m->uid, currentUser, originalUser, m->command, ipAddress, port);

  } else if (m->type_id == GETPEERNAME) {
    log_trace("Converting sockaddr_in to presentable IP address");
    inet_ntop(AF_INET, &(m->addr.sin_addr), ipAddress, INET_ADDRSTRLEN);
    log_trace("Converting sockaddr_in to IP address succeeded: %s", ipAddress);
    log_trace("Converting port to presentable format");
    port = htons(m->addr.sin_port);
    log_trace("Converting port succeeded: %d", port);
    if (!strncmp(ipAddress, "127.0.0.1", INET_ADDRSTRLEN)) {
      log_trace("IP address did not point to localhost");
      struct sockaddr_in tmpSockaddr;
      uid_t originalUser;
      log_trace("Getting the port BPF map object");
      int portMap = bpf_obj_get("/sys/fs/bpf/raw_port"); // BASH port -> IP
                                                         // #Map2
      if (portMap <= 0) {
        log_trace("No file descriptor returned for the port BPF map object");
      }
      log_trace("Getting the userport BPF map object");
      int userportMap =
          bpf_obj_get("/sys/fs/bpf/raw_userport"); // BASH port -> IP #Map2
      if (userportMap <= 0) {
        log_trace(
            "No file descriptor returned for the userport BPF map object");
      }
      if (portMap && userportMap) {
        log_trace("Looking up the sockaddr_in corresponding to port %d in the "
                  "port map",
                  port);
        bpf_map_lookup_elem(
            portMap, &port,
            &tmpSockaddr); // look up sockaddr_in from Map2 using port
        log_trace("Updating the sockaddr_in corresponding to PID %d in the "
                  "sockaddr map",
                  m->pid);
        bpf_map_update_elem(
            sockaddrMap, &m->pid, &tmpSockaddr,
            BPF_ANY); // update Map1 with current PID -> lookedup sockaddr_in
        log_trace(
            "Looking up the user corresponding to port %d in the userport map",
            port);
        bpf_map_lookup_elem(userportMap, &port, &originalUser); //
        log_trace("Updating the user corresponding to PID %d in the user map",
                  m->pid);
        bpf_map_update_elem(userMap, &m->pid, &originalUser, BPF_ANY);
        //user = &originalUser;
        close(portMap);
        close(userportMap);
      }
    }
    //uid_t userAncestor = getUID(org_user);
    //printf("%-6d %-6d %-6d %-16s %-16s %-16s %-16s %-16d\n", m->pid, m->ppid,
           //m->uid, getUser(m->uid), getUser(userAncestor), m->command, ipAddress, port);
  } else if (m->type_id == GETSOCKNAME) {
    inet_ntop(AF_INET, &(m->addr.sin_addr), ipAddress, INET_ADDRSTRLEN);
    port = htons(m->addr.sin_port);
    if (!strncmp(ipAddress, "127.0.0.1", INET_ADDRSTRLEN)) {
      int map_port =
          bpf_obj_get("/sys/fs/bpf/raw_port"); // BASH port -> IP #Map2
      int userMapport =
          bpf_obj_get("/sys/fs/bpf/raw_userport"); // BASH port -> IP #Map2

      if (map_port <= 0 && userMapport <= 0) {
        printf("No FD\n");
      } else {
        bpf_map_update_elem(
            map_port, &port, &ip,
            BPF_ANY); // update Map2 with Port -> ip (sockaddr_in)
        bpf_map_update_elem(userMapport, &port, &org_user, BPF_ANY); // update Map3 with Port -> org_user
      }

      close(userMapport);
      close(map_port);
      // ip is already looked up.
    }
    // printf("%-6d %-6d %-6d %-16s %-16s %16s %d %d\n", m->pid, m->ppid,
    // m->uid, user_c, m->command, ipAddress, port, 1);
  } else { // process tree trace back to original bash/user

    // printf("%-6d %-6d %-6d %-16s %-16s %16s %d\n", m->pid, m->ppid, m->uid,
    // user_c, m->command, "localhost", 0);
  }

  close(sockaddrMap);
  close(userMap);
  log_trace("Exiting handle_event()");
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz) {
  printf("lost event\n");
}

int main() {
  log_set_level(LOG_DEBUG);
  log_trace("%s", "Starting main()");

  printf("%-6s %-6s %-6s %-16s %-16s %-16s %-16s %-16s\n", "PID", "PPID", "UID",
         "Current User", "Origin User", "Command", "IP Address", "Port");

  log_trace("%s", "Setting LIBBPF options");
  libbpf_set_print(libbpf_print_fn);
  char log_buf[128 * 1024];
  LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_buf = log_buf,
              .kernel_log_size = sizeof(log_buf), .kernel_log_level = 1, );

  log_trace("%s", "Opening BPF skeleton object");
  struct sshtrace_bpf *skel = sshtrace_bpf__open_opts(&opts);
  if (!skel) {
    log_error("%s", "Error while opening BPF skeleton object");
    return EXIT_FAILURE;
  }

  int err = 0;

  log_trace("%s", "Loading BPF skeleton object");
  err = sshtrace_bpf__load(skel);
  if (err) {
    log_error("%s", "Error while loading BPF skeleton object");
    goto cleanup;
  }

  log_trace("%s", "Attaching BPF skeleton object");
  err = sshtrace_bpf__attach(skel);
  if (err) {
    log_error("%s", "Error while attaching BPF skeleton object");
    goto cleanup;
  }

  log_trace("%s", "Initializing perf buffer");
  struct perf_buffer *pb = perf_buffer__new(
      bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
  if (!pb) {
    log_error("%s", "Error while initializing perf buffer");
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
  log_trace("%s", "Entering cleanup");
  sshtrace_bpf__destroy(skel);
  log_trace("%s", "Finished cleanup");

  return EXIT_SUCCESS;
}
