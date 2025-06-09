#ifndef READ_WRITE_H
#define READ_WRITE_H

#include "../headers.h"
#include "../data_types.h"

static __always_inline int trace_file_operation(struct pt_regs *ctx, struct file *file, const char *operation)
{
    if (!file)
        return 0;

    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data)
    {
        return 0;
    }
    __builtin_memset(data, 0, sizeof(*data));

    struct dentry *de = NULL;
    bpf_core_read(&de, sizeof(de), &file->f_path.dentry);
    if (!de)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    struct qstr d_name = {};
    bpf_core_read(&d_name, sizeof(d_name), &de->d_name);
    if (d_name.len == 0)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    char fname[FILE_NAME_SIZE] = {};
    bpf_core_read_str(fname, sizeof(fname), d_name.name);

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->timestamp = bpf_ktime_get_ns();

    __builtin_memcpy(data->filename, fname, sizeof(data->filename));
    __builtin_memcpy(data->otype, operation, sizeof(data->otype));
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    struct inode *inode_ptr = NULL;
    bpf_core_read(&inode_ptr, sizeof(inode_ptr), &file->f_inode);
    if (!inode_ptr)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    u32 inode_num = 0;
    bpf_core_read(&inode_num, sizeof(inode_num), &inode_ptr->i_ino);

    struct inode_key key = {.inode = inode_num};

    bpf_trace_printk("LOG: filename=%s otype=%s comm=%s\n", sizeof("LOG: filename=%s otype=%s comm=%s\n"), data->filename, data->otype, data->comm);
    bpf_trace_printk("LOG: inode=%u\n", sizeof("LOG: inode=%u\n"), inode_num);

    u32 *monitored = bpf_map_lookup_elem(&monitored_inodes, &key);
    if (!monitored)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    int cgroup_id = bpf_get_current_cgroup_id();
    data->cgroup_id = cgroup_id;

    bpf_ringbuf_submit(data, 0);

    return 0;
}

#endif