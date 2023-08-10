/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __SSHTRACE_BPF_SKEL_H__
#define __SSHTRACE_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct sshtrace_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *output;
		struct bpf_map *values;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *tp_sys_enter_getpeername;
		struct bpf_program *tp_sys_exit_getpeername;
	} progs;
	struct {
		struct bpf_link *tp_sys_enter_getpeername;
		struct bpf_link *tp_sys_exit_getpeername;
	} links;
	struct sshtrace_bpf__rodata {
		char tp_btf_exec_msg[19];
	} *rodata;

#ifdef __cplusplus
	static inline struct sshtrace_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct sshtrace_bpf *open_and_load();
	static inline int load(struct sshtrace_bpf *skel);
	static inline int attach(struct sshtrace_bpf *skel);
	static inline void detach(struct sshtrace_bpf *skel);
	static inline void destroy(struct sshtrace_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
sshtrace_bpf__destroy(struct sshtrace_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
sshtrace_bpf__create_skeleton(struct sshtrace_bpf *obj);

static inline struct sshtrace_bpf *
sshtrace_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct sshtrace_bpf *obj;
	int err;

	obj = (struct sshtrace_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = sshtrace_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	sshtrace_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct sshtrace_bpf *
sshtrace_bpf__open(void)
{
	return sshtrace_bpf__open_opts(NULL);
}

static inline int
sshtrace_bpf__load(struct sshtrace_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct sshtrace_bpf *
sshtrace_bpf__open_and_load(void)
{
	struct sshtrace_bpf *obj;
	int err;

	obj = sshtrace_bpf__open();
	if (!obj)
		return NULL;
	err = sshtrace_bpf__load(obj);
	if (err) {
		sshtrace_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
sshtrace_bpf__attach(struct sshtrace_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
sshtrace_bpf__detach(struct sshtrace_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *sshtrace_bpf__elf_bytes(size_t *sz);

static inline int
sshtrace_bpf__create_skeleton(struct sshtrace_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "sshtrace_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 3;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "output";
	s->maps[0].map = &obj->maps.output;

	s->maps[1].name = "values";
	s->maps[1].map = &obj->maps.values;

	s->maps[2].name = "sshtrace.rodata";
	s->maps[2].map = &obj->maps.rodata;
	s->maps[2].mmaped = (void **)&obj->rodata;

	/* programs */
	s->prog_cnt = 2;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "tp_sys_enter_getpeername";
	s->progs[0].prog = &obj->progs.tp_sys_enter_getpeername;
	s->progs[0].link = &obj->links.tp_sys_enter_getpeername;

	s->progs[1].name = "tp_sys_exit_getpeername";
	s->progs[1].prog = &obj->progs.tp_sys_exit_getpeername;
	s->progs[1].link = &obj->links.tp_sys_exit_getpeername;

	s->data = (void *)sshtrace_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *sshtrace_bpf__elf_bytes(size_t *sz)
{
	*sz = 5776;
	return (const void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x90\x12\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x10\0\
\x01\0\x79\x11\x18\0\0\0\0\0\x7b\x1a\xf8\xff\0\0\0\0\x85\0\0\0\x0e\0\0\0\x63\
\x0a\xf4\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xf4\xff\xff\xff\xbf\xa3\0\
\0\0\0\0\0\x07\x03\0\0\xf8\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\
\x04\0\0\0\0\0\0\x85\0\0\0\x02\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\xbf\
\x16\0\0\0\0\0\0\x79\x69\x10\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\xbf\x07\0\0\0\0\0\0\
\x63\x7a\xfc\xff\0\0\0\0\x85\0\0\0\x0f\0\0\0\xbf\x08\0\0\0\0\0\0\xb7\x01\0\0\0\
\0\0\0\x63\x1a\xf8\xff\0\0\0\0\x7b\x1a\xf0\xff\0\0\0\0\x7b\x1a\xe8\xff\0\0\0\0\
\x7b\x1a\xe0\xff\0\0\0\0\x7b\x1a\xd8\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\
\0\xfc\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\
\0\x18\0\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xd8\xff\xff\xff\xbf\x92\0\0\0\
\0\0\0\x79\x09\0\0\0\0\0\0\x63\x2a\xe8\xff\0\0\0\0\x63\x8a\xd4\xff\0\0\0\0\x77\
\x07\0\0\x20\0\0\0\x63\x7a\xd0\xff\0\0\0\0\xb7\x02\0\0\x10\0\0\0\x85\0\0\0\x10\
\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xec\xff\xff\xff\xb7\x02\0\0\x10\0\0\0\
\xbf\x93\0\0\0\0\0\0\x85\0\0\0\x70\0\0\0\xbf\xa4\0\0\0\0\0\0\x07\x04\0\0\xd0\
\xff\xff\xff\xbf\x61\0\0\0\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x18\x03\0\
\0\xff\xff\xff\xff\0\0\0\0\0\0\0\0\xb7\x05\0\0\x2c\0\0\0\x85\0\0\0\x19\0\0\0\
\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x74\x70\x5f\x73\x79\x73\x5f\x65\x6e\x74\
\x65\x72\x5f\x61\x63\x63\x65\x70\x74\x44\x75\x61\x6c\x20\x42\x53\x44\x2f\x47\
\x50\x4c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\
\x30\x04\0\0\x30\x04\0\0\x49\x05\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\
\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x04\
\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\x04\x18\0\0\0\
\x19\0\0\0\x01\0\0\0\0\0\0\0\x1e\0\0\0\x01\0\0\0\x40\0\0\0\x27\0\0\0\x01\0\0\0\
\x80\0\0\0\x32\0\0\0\0\0\0\x0e\x05\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x08\0\0\0\
\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x0a\
\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\
\x02\x0c\0\0\0\x39\0\0\0\0\0\0\x08\x0d\0\0\0\x3f\0\0\0\0\0\0\x01\x04\0\0\0\x20\
\0\0\0\0\0\0\0\0\0\0\x02\x0f\0\0\0\0\0\0\0\0\0\0\x02\x10\0\0\0\x4c\0\0\0\x04\0\
\0\x04\x10\0\0\0\x58\0\0\0\x11\0\0\0\0\0\0\0\x63\0\0\0\x13\0\0\0\x10\0\0\0\x6c\
\0\0\0\x15\0\0\0\x20\0\0\0\x75\0\0\0\x18\0\0\0\x40\0\0\0\x7b\0\0\0\0\0\0\x08\
\x12\0\0\0\x90\0\0\0\0\0\0\x01\x02\0\0\0\x10\0\0\0\x9f\0\0\0\0\0\0\x08\x14\0\0\
\0\xa6\0\0\0\0\0\0\x08\x12\0\0\0\xac\0\0\0\x01\0\0\x04\x04\0\0\0\xb4\0\0\0\x16\
\0\0\0\0\0\0\0\xbb\0\0\0\0\0\0\x08\x0c\0\0\0\xc2\0\0\0\0\0\0\x01\x01\0\0\0\x08\
\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x17\0\0\0\x04\0\0\0\x08\0\0\0\0\0\0\0\x04\0\0\
\x04\x20\0\0\0\x19\0\0\0\x07\0\0\0\0\0\0\0\xd0\0\0\0\x09\0\0\0\x40\0\0\0\xdc\0\
\0\0\x0b\0\0\0\x80\0\0\0\xe0\0\0\0\x0e\0\0\0\xc0\0\0\0\xe6\0\0\0\0\0\0\x0e\x19\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x1c\0\0\0\xed\0\0\0\x04\0\0\x04\x40\0\0\0\
\x07\x01\0\0\x1d\0\0\0\0\0\0\0\x0b\x01\0\0\x1e\0\0\0\x40\0\0\0\x0e\x01\0\0\x20\
\0\0\0\x80\0\0\0\x13\x01\0\0\x22\0\0\0\0\x02\0\0\x1a\x01\0\0\x04\0\0\x04\x08\0\
\0\0\x19\0\0\0\x12\0\0\0\0\0\0\0\x26\x01\0\0\x17\0\0\0\x10\0\0\0\x2c\x01\0\0\
\x17\0\0\0\x18\0\0\0\x3a\x01\0\0\x02\0\0\0\x20\0\0\0\x3e\x01\0\0\0\0\0\x01\x08\
\0\0\0\x40\0\0\x01\x43\x01\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x03\
\0\0\0\0\x1f\0\0\0\x04\0\0\0\x06\0\0\0\x51\x01\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\
\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x21\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x0d\
\x02\0\0\0\x56\x01\0\0\x1b\0\0\0\x5a\x01\0\0\x01\0\0\x0c\x23\0\0\0\0\0\0\0\0\0\
\0\x02\x26\0\0\0\x90\x02\0\0\x04\0\0\x04\x18\0\0\0\x07\x01\0\0\x1d\0\0\0\0\0\0\
\0\x0b\x01\0\0\x1e\0\0\0\x40\0\0\0\xa9\x02\0\0\x1e\0\0\0\x80\0\0\0\x13\x01\0\0\
\x22\0\0\0\xc0\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\x56\x01\0\0\x25\0\0\0\xad\
\x02\0\0\x01\0\0\x0c\x27\0\0\0\0\0\0\0\0\0\0\x0a\x21\0\0\0\0\0\0\0\0\0\0\x03\0\
\0\0\0\x29\0\0\0\x04\0\0\0\x13\0\0\0\x1b\x05\0\0\0\0\0\x0e\x2a\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\x03\0\0\0\0\x21\0\0\0\x04\0\0\0\x0d\0\0\0\x2b\x05\0\0\0\0\0\x0e\
\x2c\0\0\0\x01\0\0\0\x33\x05\0\0\x02\0\0\x0f\0\0\0\0\x06\0\0\0\0\0\0\0\x18\0\0\
\0\x1a\0\0\0\0\0\0\0\x20\0\0\0\x39\x05\0\0\x01\0\0\x0f\0\0\0\0\x2b\0\0\0\0\0\0\
\0\x13\0\0\0\x41\x05\0\0\x01\0\0\x0f\0\0\0\0\x2d\0\0\0\0\0\0\0\x0d\0\0\0\0\x69\
\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\
\x5f\x5f\0\x74\x79\x70\x65\0\x6b\x65\x79\x5f\x73\x69\x7a\x65\0\x76\x61\x6c\x75\
\x65\x5f\x73\x69\x7a\x65\0\x6f\x75\x74\x70\x75\x74\0\x5f\x5f\x75\x33\x32\0\x75\
\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x73\x6f\x63\x6b\x61\x64\x64\x72\
\x5f\x69\x6e\0\x73\x69\x6e\x5f\x66\x61\x6d\x69\x6c\x79\0\x73\x69\x6e\x5f\x70\
\x6f\x72\x74\0\x73\x69\x6e\x5f\x61\x64\x64\x72\0\x5f\x5f\x70\x61\x64\0\x5f\x5f\
\x6b\x65\x72\x6e\x65\x6c\x5f\x73\x61\x5f\x66\x61\x6d\x69\x6c\x79\x5f\x74\0\x75\
\x6e\x73\x69\x67\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\x5f\x5f\x62\x65\x31\x36\
\0\x5f\x5f\x75\x31\x36\0\x69\x6e\x5f\x61\x64\x64\x72\0\x73\x5f\x61\x64\x64\x72\
\0\x5f\x5f\x62\x65\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\
\x72\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x6b\x65\x79\0\x76\x61\x6c\
\x75\x65\0\x76\x61\x6c\x75\x65\x73\0\x74\x72\x61\x63\x65\x5f\x65\x76\x65\x6e\
\x74\x5f\x72\x61\x77\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\0\x65\x6e\x74\0\
\x69\x64\0\x61\x72\x67\x73\0\x5f\x5f\x64\x61\x74\x61\0\x74\x72\x61\x63\x65\x5f\
\x65\x6e\x74\x72\x79\0\x66\x6c\x61\x67\x73\0\x70\x72\x65\x65\x6d\x70\x74\x5f\
\x63\x6f\x75\x6e\x74\0\x70\x69\x64\0\x6c\x6f\x6e\x67\0\x75\x6e\x73\x69\x67\x6e\
\x65\x64\x20\x6c\x6f\x6e\x67\0\x63\x68\x61\x72\0\x63\x74\x78\0\x74\x70\x5f\x73\
\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x67\x65\x74\x70\x65\x65\x72\x6e\x61\x6d\
\x65\0\x74\x70\x2f\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\
\x74\x65\x72\x5f\x67\x65\x74\x70\x65\x65\x72\x6e\x61\x6d\x65\0\x30\x3a\x32\x3a\
\x31\0\x2f\x68\x6f\x6d\x65\x2f\x61\x62\x65\x6d\x65\x6c\x76\x69\x6e\x2f\x65\x42\
\x50\x46\x2d\x52\x65\x6d\x6f\x74\x65\x2d\x43\x6c\x69\x65\x6e\x74\x2d\x54\x72\
\x61\x63\x69\x6e\x67\x2f\x73\x73\x68\x74\x72\x61\x63\x65\x2e\x62\x70\x66\x2e\
\x63\0\x20\x20\x20\x72\x65\x74\x75\x72\x6e\x20\x70\x72\x6f\x62\x65\x5f\x65\x6e\
\x74\x72\x79\x28\x63\x74\x78\x2c\x20\x28\x73\x74\x72\x75\x63\x74\x20\x73\x6f\
\x63\x6b\x61\x64\x64\x72\x5f\x69\x6e\x20\x2a\x29\x63\x74\x78\x2d\x3e\x61\x72\
\x67\x73\x5b\x31\x5d\x29\x3b\0\x20\x20\x20\x5f\x5f\x75\x36\x34\x20\x69\x64\x20\
\x3d\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\
\x69\x64\x5f\x74\x67\x69\x64\x28\x29\x3b\0\x20\x20\x20\x5f\x5f\x75\x33\x32\x20\
\x74\x69\x64\x20\x3d\x20\x28\x5f\x5f\x75\x33\x32\x29\x69\x64\x3b\0\x20\x20\x20\
\x62\x70\x66\x5f\x6d\x61\x70\x5f\x75\x70\x64\x61\x74\x65\x5f\x65\x6c\x65\x6d\
\x28\x26\x76\x61\x6c\x75\x65\x73\x2c\x20\x26\x74\x69\x64\x2c\x20\x26\x61\x64\
\x64\x72\x2c\x20\x42\x50\x46\x5f\x41\x4e\x59\x29\x3b\0\x74\x72\x61\x63\x65\x5f\
\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\x73\x79\x73\x5f\x65\x78\x69\x74\0\x72\
\x65\x74\0\x74\x70\x5f\x73\x79\x73\x5f\x65\x78\x69\x74\x5f\x67\x65\x74\x70\x65\
\x65\x72\x6e\x61\x6d\x65\0\x74\x70\x2f\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\
\x79\x73\x5f\x65\x78\x69\x74\x5f\x67\x65\x74\x70\x65\x65\x72\x6e\x61\x6d\x65\0\
\x69\x6e\x74\x20\x74\x70\x5f\x73\x79\x73\x5f\x65\x78\x69\x74\x5f\x67\x65\x74\
\x70\x65\x65\x72\x6e\x61\x6d\x65\x28\x73\x74\x72\x75\x63\x74\x20\x74\x72\x61\
\x63\x65\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\x73\x79\x73\x5f\x65\x78\
\x69\x74\x20\x2a\x63\x74\x78\x29\0\x30\x3a\x32\0\x20\x20\x20\x72\x65\x74\x75\
\x72\x6e\x20\x70\x72\x6f\x62\x65\x5f\x72\x65\x74\x75\x72\x6e\x28\x63\x74\x78\
\x2c\x20\x28\x69\x6e\x74\x29\x63\x74\x78\x2d\x3e\x72\x65\x74\x29\x3b\0\x20\x20\
\x20\x5f\x5f\x75\x33\x32\x20\x75\x69\x64\x20\x3d\x20\x62\x70\x66\x5f\x67\x65\
\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x75\x69\x64\x5f\x67\x69\x64\x28\x29\
\x20\x26\x20\x30\x78\x46\x46\x46\x46\x46\x46\x46\x46\x3b\0\x20\x20\x20\x73\x74\
\x72\x75\x63\x74\x20\x64\x61\x74\x61\x5f\x74\x20\x64\x61\x74\x61\x20\x3d\x20\
\x7b\x7d\x3b\0\x20\x20\x20\x61\x64\x64\x72\x70\x70\x20\x3d\x20\x62\x70\x66\x5f\
\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\x76\x61\
\x6c\x75\x65\x73\x2c\x20\x26\x74\x69\x64\x29\x3b\0\x20\x20\x20\x69\x66\x20\x28\
\x21\x61\x64\x64\x72\x70\x70\x29\0\x20\x20\x20\x61\x64\x64\x72\x20\x3d\x20\x2a\
\x61\x64\x64\x72\x70\x70\x3b\0\x20\x20\x20\x64\x61\x74\x61\x2e\x72\x65\x74\x20\
\x3d\x20\x72\x65\x74\x3b\0\x20\x20\x20\x64\x61\x74\x61\x2e\x75\x69\x64\x20\x3d\
\x20\x75\x69\x64\x3b\0\x20\x20\x20\x5f\x5f\x75\x33\x32\x20\x70\x69\x64\x20\x3d\
\x20\x69\x64\x20\x3e\x3e\x20\x33\x32\x3b\0\x20\x20\x20\x64\x61\x74\x61\x2e\x70\
\x69\x64\x20\x3d\x20\x70\x69\x64\x3b\0\x20\x20\x20\x62\x70\x66\x5f\x67\x65\x74\
\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x63\x6f\x6d\x6d\x28\x26\x64\x61\x74\x61\
\x2e\x63\x6f\x6d\x6d\x61\x6e\x64\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x64\x61\
\x74\x61\x2e\x63\x6f\x6d\x6d\x61\x6e\x64\x29\x29\x3b\0\x20\x20\x20\x62\x70\x66\
\x5f\x70\x72\x6f\x62\x65\x5f\x72\x65\x61\x64\x5f\x75\x73\x65\x72\x28\x26\x64\
\x61\x74\x61\x2e\x61\x64\x64\x72\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x64\x61\
\x74\x61\x2e\x61\x64\x64\x72\x29\x2c\x20\x61\x64\x64\x72\x29\x3b\0\x20\x20\x20\
\x62\x70\x66\x5f\x70\x65\x72\x66\x5f\x65\x76\x65\x6e\x74\x5f\x6f\x75\x74\x70\
\x75\x74\x28\x63\x74\x78\x2c\x20\x26\x6f\x75\x74\x70\x75\x74\x2c\x20\x42\x50\
\x46\x5f\x46\x5f\x43\x55\x52\x52\x45\x4e\x54\x5f\x43\x50\x55\x2c\x20\x26\x64\
\x61\x74\x61\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x64\x61\x74\x61\x29\x29\x3b\0\
\x74\x70\x5f\x62\x74\x66\x5f\x65\x78\x65\x63\x5f\x6d\x73\x67\0\x4c\x49\x43\x45\
\x4e\x53\x45\0\x2e\x6d\x61\x70\x73\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\
\x65\x6e\x73\x65\0\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x24\0\0\0\x24\0\0\0\
\xc4\x01\0\0\xe8\x01\0\0\x34\0\0\0\x08\0\0\0\x73\x01\0\0\x01\0\0\0\0\0\0\0\x24\
\0\0\0\xc5\x02\0\0\x01\0\0\0\0\0\0\0\x28\0\0\0\x10\0\0\0\x73\x01\0\0\x06\0\0\0\
\0\0\0\0\x9b\x01\0\0\xd5\x01\0\0\x32\xf4\0\0\x10\0\0\0\x9b\x01\0\0\x15\x02\0\0\
\x0f\x64\0\0\x18\0\0\0\x9b\x01\0\0\x3f\x02\0\0\x0a\x6c\0\0\x28\0\0\0\x9b\x01\0\
\0\0\0\0\0\0\0\0\0\x40\0\0\0\x9b\x01\0\0\x59\x02\0\0\x04\x74\0\0\x60\0\0\0\x9b\
\x01\0\0\xd5\x01\0\0\x04\xf4\0\0\xc5\x02\0\0\x15\0\0\0\0\0\0\0\x9b\x01\0\0\xe6\
\x02\0\0\0\x04\x01\0\x08\0\0\0\x9b\x01\0\0\x2c\x03\0\0\x27\x0c\x01\0\x10\0\0\0\
\x9b\x01\0\0\x15\x02\0\0\x0f\x8c\0\0\x20\0\0\0\x9b\x01\0\0\x3f\x02\0\0\x0a\x94\
\0\0\x28\0\0\0\x9b\x01\0\0\x58\x03\0\0\x10\x98\0\0\x40\0\0\0\x9b\x01\0\0\x8f\
\x03\0\0\x12\xa4\0\0\x70\0\0\0\x9b\x01\0\0\0\0\0\0\0\0\0\0\x78\0\0\0\x9b\x01\0\
\0\xab\x03\0\0\x0d\xac\0\0\x90\0\0\0\x9b\x01\0\0\xdb\x03\0\0\x08\xb0\0\0\x98\0\
\0\0\x9b\x01\0\0\0\0\0\0\0\0\0\0\xb0\0\0\0\x9b\x01\0\0\xeb\x03\0\0\x0b\xbc\0\0\
\xb8\0\0\0\x9b\x01\0\0\xfe\x03\0\0\x0d\xc8\0\0\xc0\0\0\0\x9b\x01\0\0\x11\x04\0\
\0\x0d\xc4\0\0\xc8\0\0\0\x9b\x01\0\0\x24\x04\0\0\x13\x90\0\0\xd0\0\0\0\x9b\x01\
\0\0\x3d\x04\0\0\x0d\xc0\0\0\xd8\0\0\0\x9b\x01\0\0\x50\x04\0\0\x04\xcc\0\0\xe8\
\0\0\0\x9b\x01\0\0\x8e\x04\0\0\x1e\xd0\0\0\xf8\0\0\0\x9b\x01\0\0\x8e\x04\0\0\
\x04\xd0\0\0\x18\x01\0\0\x9b\x01\0\0\0\0\0\0\0\0\0\0\x20\x01\0\0\x9b\x01\0\0\
\xcb\x04\0\0\x04\xd4\0\0\x58\x01\0\0\x9b\x01\0\0\x2c\x03\0\0\x04\x0c\x01\0\x10\
\0\0\0\x73\x01\0\0\x01\0\0\0\0\0\0\0\x1c\0\0\0\x95\x01\0\0\0\0\0\0\xc5\x02\0\0\
\x01\0\0\0\x08\0\0\0\x26\0\0\0\x28\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x03\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf3\0\0\0\0\0\x05\0\x58\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x8b\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x70\0\0\0\0\0\0\
\0\x21\0\0\0\x11\0\x09\0\x18\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x4e\0\0\0\x12\0\
\x05\0\0\0\0\0\0\0\0\0\x68\x01\0\0\0\0\0\0\x14\0\0\0\x11\0\x09\0\0\0\0\0\0\0\0\
\0\x18\0\0\0\0\0\0\0\x28\0\0\0\x11\0\x07\0\0\0\0\0\0\0\0\0\x13\0\0\0\0\0\0\0\
\xeb\0\0\0\x11\0\x08\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x01\
\0\0\0\x05\0\0\0\x78\0\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\x28\x01\0\0\0\0\0\0\x01\
\0\0\0\x07\0\0\0\x04\x04\0\0\0\0\0\0\x04\0\0\0\x07\0\0\0\x10\x04\0\0\0\0\0\0\
\x04\0\0\0\x05\0\0\0\x28\x04\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x40\x04\0\0\0\0\0\
\0\x04\0\0\0\x09\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x3c\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x60\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x80\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xa0\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\xb8\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xc8\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xd8\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xe8\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xf8\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x08\x01\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x18\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x28\x01\0\0\0\0\0\
\0\x04\0\0\0\x02\0\0\0\x38\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x48\x01\0\0\0\0\
\0\0\x04\0\0\0\x02\0\0\0\x58\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x68\x01\0\0\0\
\0\0\0\x04\0\0\0\x02\0\0\0\x78\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x88\x01\0\0\
\0\0\0\0\x04\0\0\0\x02\0\0\0\x98\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xa8\x01\0\
\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xb8\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xc8\x01\
\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xd8\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xe8\
\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xf8\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\
\x14\x02\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x2c\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\0\
\0\x0e\x10\x13\x11\x0f\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\
\x2e\x65\x78\x74\0\x6f\x75\x74\x70\x75\x74\0\x2e\x6d\x61\x70\x73\0\x76\x61\x6c\
\x75\x65\x73\0\x74\x70\x5f\x62\x74\x66\x5f\x65\x78\x65\x63\x5f\x6d\x73\x67\0\
\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x6c\x69\x63\x65\x6e\x73\
\x65\0\x74\x70\x5f\x73\x79\x73\x5f\x65\x78\x69\x74\x5f\x67\x65\x74\x70\x65\x65\
\x72\x6e\x61\x6d\x65\0\x2e\x72\x65\x6c\x74\x70\x2f\x73\x79\x73\x63\x61\x6c\x6c\
\x73\x2f\x73\x79\x73\x5f\x65\x78\x69\x74\x5f\x67\x65\x74\x70\x65\x65\x72\x6e\
\x61\x6d\x65\0\x74\x70\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x67\x65\x74\
\x70\x65\x65\x72\x6e\x61\x6d\x65\0\x2e\x72\x65\x6c\x74\x70\x2f\x73\x79\x73\x63\
\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x67\x65\x74\x70\
\x65\x65\x72\x6e\x61\x6d\x65\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\
\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\
\x4c\x49\x43\x45\x4e\x53\x45\0\x4c\x42\x42\x31\x5f\x32\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xca\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x95\x11\0\0\0\0\0\0\xfa\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa8\
\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x70\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa4\0\0\0\x09\0\0\0\
\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\x0f\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x0f\0\
\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x6a\0\0\0\x01\0\0\0\x06\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\0\0\0\0\0\0\0\x68\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x66\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x40\x0f\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x0f\0\0\0\x05\0\0\0\x08\0\0\
\0\0\0\0\0\x10\0\0\0\0\0\0\0\xda\0\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x18\x02\0\0\0\0\0\0\x13\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x46\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2b\x02\0\
\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x1b\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\x02\0\0\0\0\0\0\x38\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe6\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\x02\0\0\0\0\0\0\x91\x09\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe2\0\0\0\x09\0\0\0\x40\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x60\x0f\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x0f\0\0\0\x0a\
\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x0b\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x04\x0c\0\0\0\0\0\0\x3c\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\xa0\x0f\0\0\0\0\0\0\xf0\x01\0\0\0\0\0\0\x0f\0\0\0\x0c\0\0\0\x08\0\0\0\0\0\
\0\0\x10\0\0\0\0\0\0\0\x38\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\
\0\0\x90\x11\0\0\0\0\0\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xd2\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x0e\0\0\
\0\0\0\0\xf0\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\
\0\0";
}

#ifdef __cplusplus
struct sshtrace_bpf *sshtrace_bpf::open(const struct bpf_object_open_opts *opts) { return sshtrace_bpf__open_opts(opts); }
struct sshtrace_bpf *sshtrace_bpf::open_and_load() { return sshtrace_bpf__open_and_load(); }
int sshtrace_bpf::load(struct sshtrace_bpf *skel) { return sshtrace_bpf__load(skel); }
int sshtrace_bpf::attach(struct sshtrace_bpf *skel) { return sshtrace_bpf__attach(skel); }
void sshtrace_bpf::detach(struct sshtrace_bpf *skel) { sshtrace_bpf__detach(skel); }
void sshtrace_bpf::destroy(struct sshtrace_bpf *skel) { sshtrace_bpf__destroy(skel); }
const void *sshtrace_bpf::elf_bytes(size_t *sz) { return sshtrace_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
sshtrace_bpf__assert(struct sshtrace_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->rodata->tp_btf_exec_msg) == 19, "unexpected size of 'tp_btf_exec_msg'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __SSHTRACE_BPF_SKEL_H__ */
