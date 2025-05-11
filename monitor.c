#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/file.h>

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

BPF_PERF_OUTPUT(events);
BPF_HASH(monitored_inodes, struct inode_key, u32, 256);
BPF_PERCPU_ARRAY(logs_data, struct data_t, 1);

static int trace_file_operation(struct pt_regs *ctx, struct file *file, const char *operation) {
    if (!file || !file->f_path.dentry || !file->f_inode)
        return 0;

    int zero = 0;

    struct data_t *data = logs_data.lookup(&zero);
    if (!data)
        return 0;
    __builtin_memset(data, 0, sizeof(*data));

    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name;
    if (d_name.len == 0)
        return 0;

    char buf[128] = {};
    bpf_probe_read_kernel_str(&buf, sizeof(buf), d_name.name);

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->timestamp = bpf_ktime_get_ns();

    bpf_probe_read_kernel_str(&data->filename, sizeof(data->filename), buf);
    bpf_probe_read_kernel_str(&data->otype, sizeof(data->otype), operation);
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    struct inode *inode = file->f_inode;
    u32 inode_num = inode->i_ino;
    struct inode_key key = {.inode = inode_num};
    if (!monitored_inodes.lookup(&key)) {
        bpf_trace_printk("Inode not monitored: %u\n", inode_num);
        bpf_trace_printk("filename: %s\n", data->filename);
        return 0;
    }

    bpf_trace_printk("filename in inode: %s\n", data->filename);
    events.perf_submit(ctx, data, sizeof(*data));

    return 0;
}

int trace_read(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count) {
    if (!file)
        return 0;

    char OPRN[] = "READ";
    return trace_file_operation(ctx, file, OPRN);
}

int trace_write(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count) {
    if (!file)
    return 0;

    char OPRN[] = "WRITE";
    return trace_file_operation(ctx, file, OPRN);
}

int trace_rename(struct pt_regs *ctx, struct file *oldfile, struct file *newfile) {
    if (!oldfile || !newfile)
        return 0;

    char OPRN[] = "RENAME";
    return trace_file_operation(ctx, oldfile, OPRN);
}

int trace_create(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count) {
    if (!file)
        return 0;

    char OPRN[] = "CREATE";
    return trace_file_operation(ctx, file, OPRN);
}

int trace_delete(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count) {
    if (!file)
        return 0;

    char OPRN[] = "DELETE";
    return trace_file_operation(ctx, file, OPRN);
}
