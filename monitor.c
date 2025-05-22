// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct inode_key {
    u32 inode;
};

struct data_t {
    u32 pid;
    u32 uid;
    char filename[128];
    char comm[16];
    u64 timestamp;
    char otype[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct inode_key);
    __type(value, u32);
    __uint(max_entries, 256);
} monitored_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct data_t);
    __uint(max_entries, 1);
} logs_data SEC(".maps");

static __always_inline int trace_file_operation(struct pt_regs *ctx, struct file *file, const char *operation)
{
    if (!file)
        return 0;

    u32 zero = 0;
    struct data_t *data = bpf_map_lookup_elem(&logs_data, &zero);
    if (!data)
        return 0;
    __builtin_memset(data, 0, sizeof(*data));

    struct dentry *de = NULL;
    bpf_core_read(&de, sizeof(de), &file->f_path.dentry);
    if (!de)
        return 0;

    struct qstr d_name = {};
    bpf_core_read(&d_name, sizeof(d_name), &de->d_name);
    if (d_name.len == 0)
        return 0;

    char fname[128] = {};
    bpf_core_read_str(fname, sizeof(fname), d_name.name);

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->timestamp = bpf_ktime_get_ns();

    __builtin_memcpy(data->filename, fname, sizeof(data->filename));
    __builtin_memcpy(data->otype, operation, sizeof(data->otype));
    bpf_get_current_comm(&data->comm, sizeof(data->comm));


    char *fmt = "LOG: pid, uid, filename, otype, comm";
    bpf_trace_printk(fmt, sizeof(fmt));
    bpf_trace_printk(data->pid, sizeof(data->pid));
    bpf_trace_printk(data->uid, sizeof(data->uid));
    bpf_trace_printk(data->filename, sizeof(data->filename));
    bpf_trace_printk(data->otype, sizeof(data->otype));
    bpf_trace_printk(data->comm, sizeof(data->comm));

    struct inode *inode = NULL;
    bpf_core_read(&inode, sizeof(inode), &file->f_inode);
    if (!inode)
        return 0;

    u32 inode_num = 0;
    bpf_core_read(&inode_num, sizeof(inode_num), &inode->i_ino);

    struct inode_key key = {.inode = inode_num};
    u32 *monitored = bpf_map_lookup_elem(&monitored_inodes, &key);
    if (!monitored)
        return 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    return 0;
}

SEC("kprobe/vfs_read")
int trace_read(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    char OPRN[] = "READ";
    return trace_file_operation(ctx, file, OPRN);
}

SEC("kprobe/vfs_write")
int trace_write(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    char OPRN[] = "WRITE";
    return trace_file_operation(ctx, file, OPRN);
}

SEC("kprobe/vfs_rename")
int trace_rename(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    char OPRN[] = "RENAME";
    return trace_file_operation(ctx, file, OPRN);
}

SEC("kprobe/vfs_create")
int BPF_KPROBE(trace_create, struct file *file, umode_t mode, bool excl)
{
    char OPRN[] = "CREATE";
    return trace_file_operation(ctx, file, OPRN);
}

SEC("kprobe/vfs_unlink")
int trace_delete(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM2(ctx); // file being deleted
    char OPRN[] = "DELETE";
    return trace_file_operation(ctx, file, OPRN);
}