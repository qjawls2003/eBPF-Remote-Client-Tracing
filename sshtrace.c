#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sshtrace.h"
#include "sshtrace.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{ 
	struct data_t *m = data;
	//char str1[] = "sshd";
	//char str2[] = "ls";
	//struct sockaddr temp = *m->client_ip;
	//printf("Here \n");

    struct sockaddr_in ip;
	char ipAddress[INET_ADDRSTRLEN] = {0};
    uint16_t port;
	int err;
	int val = bpf_obj_get("/sys/fs/bpf/raw_sockaddr"); //BASH PID -> IP
    if (val <= 0) {
        printf("No FD\n");
    } else {
        err = bpf_map_lookup_elem(val, &m->ppid, &ip);
    }

	if (!err){
	//inet_ntop(AF_INET, &(ip.sin_addr), ipAddress, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(m->addr.sin_addr), ipAddress, INET_ADDRSTRLEN);
    port = htons(m->addr.sin_port);

    printf("%-6d %-6d %-16s %16s %d\n", m->pid, m->ppid, m->command, ipAddress, port);
	} else {
	inet_ntop(AF_INET, &(m->addr.sin_addr), ipAddress, INET_ADDRSTRLEN);
    port = htons(m->addr.sin_port);
    printf("%-6d %-6d %-16s %16s %d\n", m->pid, m->ppid, m->command, ipAddress, port);
	}
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

int main()
{
    printf("%s", "Starting...\n");
	printf("%-6s %-6s %-16s %16s\n", "PID", "PPID", "Command", "IP Address");

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
