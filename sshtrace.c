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
#include "sshtrace.h"
#include "sshtrace.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

const char* getUser(uid_t uid) {
	struct passwd *pws;
	pws = getpwuid(uid);
	return pws->pw_name;
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{ 
	struct data_t *m = data;
    struct sockaddr_in ip;
	char ipAddress[INET_ADDRSTRLEN] = {0};
    uint16_t port;
	int err;
	int map_pid = bpf_obj_get("/sys/fs/bpf/raw_sockaddr"); //BASH PID -> IP #Map1
    if (map_pid <= 0) {
        printf("No FD\n");
    } else {
        err = bpf_map_lookup_elem(map_pid, &m->ppid, &ip);
    }
	const char* user = getUser(m->uid);

	if (!err && (m->type_id==3)){
		inet_ntop(AF_INET, &(ip.sin_addr), ipAddress, INET_ADDRSTRLEN);
		port = htons(ip.sin_port);

		//inet_ntop(AF_INET, &(m->addr.sin_addr), ipAddress, INET_ADDRSTRLEN);
		//port = htons(m->addr.sin_port);
		printf("%-6d %-6d %-6d %-16s %-16s %16s %d\n", m->pid, m->ppid, m->uid, user, m->command, ipAddress, port);

	} else if (m->type_id==1) { //getpeername
		inet_ntop(AF_INET, &(m->addr.sin_addr), ipAddress, INET_ADDRSTRLEN);
		port = htons(m->addr.sin_port);
		if (!strncmp(ipAddress,"127.0.0.1",INET_ADDRSTRLEN)) {
			int err, err2;
			struct sockaddr_in ip2;
			int map_port = bpf_obj_get("/sys/fs/bpf/raw_port"); //BASH port -> IP #Map2
			if (map_port <= 0) {
				printf("No FD\n");
			} else {
				err = bpf_map_lookup_elem(map_port, &port, &ip2);//look up sockaddr_in from Map2 using port
				err2 = bpf_map_update_elem(map_pid, &m->pid, &ip2, BPF_ANY); //update Map1 with current PID -> lookedup sockaddr_in

//int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
			}
		}
		printf("%-6d %-6d %-6d %-16s %-16s %16s %d\n", m->pid, m->ppid, m->uid,user, m->command, ipAddress, port);
	} else if (m->type_id==2) { //getsockname
		inet_ntop(AF_INET, &(m->addr.sin_addr), ipAddress, INET_ADDRSTRLEN);
		port = htons(m->addr.sin_port);
		if (!strncmp(ipAddress,"127.0.0.1",INET_ADDRSTRLEN)) {
			int err;
			int map_port = bpf_obj_get("/sys/fs/bpf/raw_port"); //BASH port -> IP #Map2
			if (map_port <= 0) {
				printf("No FD\n");
			} else {
				err = bpf_map_update_elem(map_port, &port, &ip, BPF_ANY);  //update Map2 with Port -> ip (sockaddr_in)
			}
			//ip is already looked up. 
		}
		printf("%-6d %-6d %-6d %-16s %-16s %16s %d\n", m->pid, m->ppid, m->uid,user, m->command, ipAddress, port);
	} else { //process tree trace back to original bash/user
		printf("%-6d %-6d %-6d %-16s %-16s %16s %d\n", m->pid, m->ppid, m->uid, user, m->command, "localhost", 0);
	}
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

int main()
{
    printf("%s", "Starting...\n");
	printf("%-6s %-6s %-6s %-16s %-16s %16s\n", "PID", "PPID", "UID", "User", "Command", "IP Address");

	struct sshtrace_bpf *skel;
	// struct bpf_object_open_opts *o;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	char log_buf[128 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);

	skel = sshtrace_bpf__open_opts(&opts);
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = sshtrace_bpf__load(skel);
	/*
	// Print the verifier log
	for (int i=0; i < sizeof(log_buf); i++) {
		if (log_buf[i] == 0 && log_buf[i+1] == 0) {
			break;
		}
		printf("%c", log_buf[i]);
	}
	*/
	if (err) {
		printf("Failed to load BPF object\n");
		sshtrace_bpf__destroy(skel);
		return 1;
	}

	// Attach the progams to the events
	err = sshtrace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		sshtrace_bpf__destroy(skel);
        return 1;
	}
	    //printf("%s", "Creating buffer...");
	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		sshtrace_bpf__destroy(skel);
        return 1;
	}

	while (true) {
		
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	perf_buffer__free(pb);
	sshtrace_bpf__destroy(skel);
	return -err;
}
