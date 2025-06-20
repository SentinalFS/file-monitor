#ifndef READ_WRITE_H
#define READ_WRITE_H

#include "../headers.h"
#include "../data_types.h"
#include "../utils/utils.h"

static __always_inline int trace_file_operation(struct pt_regs *ctx, struct file *file, const char *operation)
{
    if (!file)
        return 0;

    // Declare the ring buffer for events
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data)
    {
        return 0;
    }
    __builtin_memset(data, 0, sizeof(*data));

    // Check if the file pointer is valid, get the dentry from the file structure
    struct dentry *de = NULL;
    bpf_core_read(&de, sizeof(de), &file->f_path.dentry);
    if (!de)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    // Get filename
    struct qstr d_name = {};
    bpf_core_read(&d_name, sizeof(d_name), &de->d_name);
    if (d_name.len == 0)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    // Get parent dentry
    struct dentry *parent_de = NULL;
    bpf_core_read(&parent_de, sizeof(parent_de), &de->d_parent);
    if (!parent_de)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    // Get parent filename
    struct qstr parent_d_name = {};
    bpf_core_read(&parent_d_name, sizeof(parent_d_name), &parent_de->d_name);
    if (parent_d_name.len == 0)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    // Get Inode from file structure
    struct inode *inode_ptr = NULL;
    bpf_core_read(&inode_ptr, sizeof(inode_ptr), &file->f_inode);
    if (!inode_ptr)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    // Get the current cgroup ID
    int cgroup_id = bpf_get_current_cgroup_id();

    // Copy the data into the event structure
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->timestamp = bpf_ktime_get_ns();
    data->cgroup_id = cgroup_id;

    bpf_core_read_str(data->filename, sizeof(data->filename), d_name.name);
    bpf_core_read_str(data->parent_filename, sizeof(data->parent_filename), parent_d_name.name);
    bpf_core_read(&data->inode, sizeof(data->inode), &inode_ptr->i_ino);
    __builtin_memcpy(data->otype, operation, sizeof(data->otype));

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    bpf_trace_printk("LOG: filename=%s otype=%s comm=%s\n", sizeof("LOG: filename=%s otype=%s comm=%s\n"), data->filename, data->otype, data->comm);
    bpf_trace_printk("LOG: inode=%u\n", sizeof("LOG: inode=%u\n"), data->inode);

    bpf_ringbuf_submit(data, 0);

    return 0;
}

#endif