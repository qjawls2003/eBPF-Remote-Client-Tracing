#define _POSIX_SOURCE

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

#include "log.c/src/log.h"
#include "sshtrace.h"
#include "sshtrace.skel.h"

#define GETPEERNAME 1
#define GETSOCKNAME 2
#define EXECVE 3

int count = 0;

static int logLevel = LOG_INFO; // set desired logging level here

volatile sig_atomic_t intSignal;

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

struct ipData ipHelper(struct sockaddr *ipRaw) {
  struct ipData ipRes ={0};
  switch (ipRaw->sa_family) {
  case AF_INET: { // IPv4
    struct sockaddr_in * ip = (struct sockaddr_in *)ipRaw;
    inet_ntop(AF_INET, &(ip->sin_addr), ipRes.ipAddress, INET_ADDRSTRLEN);
    ipRes.port = htons(ip->sin_port);
    log_info("Converting sockaddr to IPv4 address Successful: %s %d", ipRes.ipAddress,ipRes.port);
    return ipRes;
  }
  case AF_INET6: { // IPv6
    struct sockaddr_in6 * ip6 = (struct sockaddr_in6 *)ipRaw;
    inet_ntop(AF_INET6, &(ip6->sin6_addr), ipRes.ipAddress, INET6_ADDRSTRLEN);
    ipRes.port = htons(ip6->sin6_port);
    log_info("Converting sockaddr to IPv6 address Successful: %s %d", ipRes.ipAddress,ipRes.port);
    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
	       ip6->sin6_addr.s6_addr[0],  ip6->sin6_addr.s6_addr[1],
	       ip6->sin6_addr.s6_addr[2],  ip6->sin6_addr.s6_addr[3],
	       ip6->sin6_addr.s6_addr[4],  ip6->sin6_addr.s6_addr[5],
	       ip6->sin6_addr.s6_addr[6],  ip6->sin6_addr.s6_addr[7],
	       ip6->sin6_addr.s6_addr[8],  ip6->sin6_addr.s6_addr[9],
	       ip6->sin6_addr.s6_addr[10], ip6->sin6_addr.s6_addr[11],
	       ip6->sin6_addr.s6_addr[12], ip6->sin6_addr.s6_addr[13],
	       ip6->sin6_addr.s6_addr[14], ip6->sin6_addr.s6_addr[15]);
    return ipRes;
  }
  default:
    log_trace("Converting sockaddr_in to IP address Not Successful");
    return ipRes;
  }
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
    log_trace("Unable to find username for UID %d", uid);
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
    log_warn("Failed to open %s, returning default PID 1", file);
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
    log_warn("Failed to open %s, returning empty command", file);
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
    log_warn("Failed to open %s, returning empty UID", file);
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
  count++;
  struct data_t *m = data;
  struct sockaddr ip = {0};
  //char ipAddress[INET6_ADDRSTRLEN] = {0};

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
    log_trace("Ancestor sockaddr found (%s) with PID (%d)", m->command, ppid);
  } else {
    log_trace("Ancestor sockaddr not found (%s) with PID (%d)", m->command, ppid);
    ip = m->addr;
  }

  
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
        sockaddrErr =
            bpf_map_lookup_elem(sockaddrMap, &sshdPID, &ip); // update ip
        userErr = bpf_map_lookup_elem(userMap, &sshdPID,
                                      &org_user); // update org_user
        if (sockaddrErr != 0) {
          log_trace(
              "Couldn't find a corresponding sockaddr_in for the sshd process");
        } else {
          log_trace("Found a corresponding sockaddr_in for the sshd process");
          break;
        }
      }
      ppid = ancestorPID;
    }
    log_debug("Reporting %d as the originating PID: %d Command: %s", sshdPID,
              sshdFound, comm);
    free(comm);
    if (sshdFound == false) {
      close(sockaddrMap);
      close(userMap);
      return;
    }
    struct ipData ipRes = ipHelper(&ip);

    /*
    log_trace("Converting sockaddr_in to presentable IP address");
    inet_ntop(AF_INET, &(ip.sin_addr), ipAddress, INET_ADDRSTRLEN);
    log_trace("Converting sockaddr_in to IP address succeeded (%s)", ipAddress);
    log_trace("Converting port to presentable format");
    port = htons(ip.sin_port);
    log_trace("Converting port succeeded (%d)", port);
    log_trace("Using this PID for getUID (%d)", sshdPID);
    */
    char *originalUser;

    if (userErr == 0) {
      log_trace("OriginalUser found");
      originalUser = getUser(org_user);
    } else { // case when localhost ssh to localhost
      log_trace("OriginalUser not found, use currentUser");
      uid_t originalUID = getUID(sshdPID);
      originalUser = getUser(originalUID);
    }
    char *currentUser = getUser(m->uid);

    printf("%-6d %-6d %-6d %-16s %-16s %-16s %-16s %-16d\n", m->pid, m->ppid,
           m->uid, currentUser, originalUser, m->command, ipRes.ipAddress, ipRes.port);

    free(currentUser);
    free(originalUser);
  } else if (m->type_id == GETPEERNAME) {
    struct ipData ipRes = ipHelper(&m->addr);
    /*
    log_trace("Converting sockaddr_in to presentable IP address");
    inet_ntop(AF_INET, &(m->addr.sin_addr), ipAddress, INET_ADDRSTRLEN);
    log_trace("Converting sockaddr_in to IP address succeeded: %s", ipAddress);
    log_trace("Converting port to presentable format");
    port = htons(m->addr.sin_port);
    log_trace("Converting port succeeded: %d", port);
    */
    log_trace("Converting sockaddr to IP address succeeded: %s", ipRes.ipAddress);
    if (!strncmp(ipRes.ipAddress, "127.0.0.1", INET_ADDRSTRLEN)) {
      log_trace("Client IP address is localhost");
      struct sockaddr tmpSockaddr;
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
            portMap, &ipRes.port,
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
        bpf_map_lookup_elem(userportMap, &ipRes.port, &originalUser); //
        log_trace("Updating the user corresponding to PID %d in the user map",
                  m->pid);
        bpf_map_update_elem(userMap, &m->pid, &originalUser, BPF_ANY);
        // user = &originalUser;
      }
      close(portMap);
      close(userportMap);
    }
    // uid_t userAncestor = getUID(org_user);
    // printf("%-6d %-6d %-6d %-16s %-16s %-16s %-16s %-16d\n", m->pid, m->ppid,
    // m->uid, getUser(m->uid), getUser(userAncestor), m->command, ipAddress,
    // port);
  } else if (m->type_id == GETSOCKNAME) {
     struct ipData ipRes = ipHelper(&m->addr);
    /*
    inet_ntop(AF_INET, &(m->addr.sin_addr), ipAddress, INET_ADDRSTRLEN);
    port = htons(m->addr.sin_port);
    log_trace("Converting getsockname() port and received %d", port);
    */
    log_trace("Converting sockaddr to IP address succeeded: %s", ipRes.ipAddress);
    if (!strncmp(ipRes.ipAddress, "127.0.0.1", INET_ADDRSTRLEN)) {
      log_trace("Your IP address is localhost");
      int map_port =
          bpf_obj_get("/sys/fs/bpf/raw_port"); // BASH port -> IP #Map2
      int userMapport =
          bpf_obj_get("/sys/fs/bpf/raw_userport"); // BASH port -> IP #Map2
      if (userErr) {
        org_user = m->uid;
      }
      if (map_port && userMapport) {
        // I feel like we need to have a while loop here to crawl the process
        // tree
        sockaddrErr = bpf_map_lookup_elem(sockaddrMap, &m->ppid, &ip);
        if (sockaddrErr == 0) {
          log_trace("Found sockaddr_in for PID %d", m->ppid);
        } else {
          log_trace("Could not find sockaddr_in for PID %d", m->ppid);
        }
        //struct ipData ipRes2 = ipHelper(&ip);
        //inet_ntop(AF_INET, &(ip.sin_addr), ipAddress, INET_ADDRSTRLEN);
        //log_trace("Updating the IP: %s corresponding to port %d", ipAddress,port);
        bpf_map_update_elem(
            map_port, &ipRes.port, &ip,
            BPF_ANY); // update Map2 with Port -> ip (sockaddr_in)
        log_trace("Updating the UID %d corresponding to port %d", org_user,
                  port);
        bpf_map_update_elem(userMapport, &ipRes.port, &org_user,
                            BPF_ANY); // update Map3 with Port -> org_user
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
  log_set_level(logLevel);
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
