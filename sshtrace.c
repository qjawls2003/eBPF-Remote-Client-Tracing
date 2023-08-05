#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
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
	char ipAddress[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(m->client_ip), ipAddress, INET_ADDRSTRLEN);
	printf("%-6d %-6d %-16s %s %s\n", m->pid, m->uid, m->command, ipAddress, m->message);
	//printf("%-6d %-6d %-16s %-16d %s %s\n", m->pid, m->uid, m->command, m->sockaddr.sa_family, m->sockaddr.sa_data, m->message);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

int main()
{
    printf("%s", "Starting...\n");
	struct sshtrace_bpf *skel;
	// struct bpf_object_open_opts *o;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	char log_buf[64 * 1024];
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
