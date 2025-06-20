#ifndef DELETE_H
#define DELETE_H

#include "../headers.h"
#include "../data_types.h"
#include "../utils/utils.h"

static __always_inline int trace_file_delete(struct pt_regs *ctx, struct dentry *de)
{
    if (!de)
    {
        return 0;
    }

    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data)
    {
        return 0;
    }
    __builtin_memset(data, 0, sizeof(*data));

    // specify the operation type
    char OPRN[] = "DELETE";

    // Read filename from dentry
    struct qstr d_name_qstr = {};
    bpf_core_read(&d_name_qstr, sizeof(d_name_qstr), &de->d_name);
    if (d_name_qstr.len <= 0 || !d_name_qstr.name || d_name_qstr.name == (void *)-1UL || d_name_qstr.name == NULL)
    {
        DISCARD_AND_RETURN(data);
    }

    // Get parent dentry
    struct dentry *parent_de = NULL;
    bpf_core_read(&parent_de, sizeof(parent_de), &de->d_parent);
    if (!parent_de)
    {
        DISCARD_AND_RETURN(data);
    }

    // Read parent filename from parent dentry
    struct qstr parent_d_name_qstr = {};
    bpf_core_read(&parent_d_name_qstr, sizeof(parent_d_name_qstr), &parent_de->d_name);
    if (parent_d_name_qstr.len <= 0 || !parent_d_name_qstr.name || parent_d_name_qstr.name == (void *)-1UL || parent_d_name_qstr.name == NULL)
    {
        DISCARD_AND_RETURN(data);
    }

    // Check for negative dentries
    unsigned char d_parent_flags = 0;
    unsigned char d_flags = 0;
    bpf_core_read(&d_parent_flags, sizeof(d_parent_flags), &parent_de->d_flags);
    bpf_core_read(&d_flags, sizeof(d_flags), &de->d_flags);
    if ((d_parent_flags & DCACHE_NEGATIVE_DENTRY) || (d_flags & DCACHE_NEGATIVE_DENTRY)) {
        bpf_trace_printk("Negative dentry detected: parent flags: %u, dentry flags: %u\n", d_parent_flags, d_flags);
        DISCARD_AND_RETURN(data);
    }

    // Get the inode number
    struct inode *inode_ptr = NULL;
    bpf_core_read(&inode_ptr, sizeof(inode_ptr), &de->d_inode);
    if (inode_ptr)
        bpf_core_read(&data->inode, sizeof(data->inode), &inode_ptr->i_ino);
    else
        data->inode = NEGATIVE_INODE_NUMBER;

    // Get cgroup ID
    int cgroup_id = bpf_get_current_cgroup_id();

    // Copy data into the data structure
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->timestamp = bpf_ktime_get_ns();
    data->cgroup_id = cgroup_id;

    bpf_core_read_str(data->filename, sizeof(data->filename), d_name_qstr.name);
    bpf_core_read_str(data->parent_filename, sizeof(data->parent_filename), parent_d_name_qstr.name);
    __builtin_memcpy(data->otype, OPRN, sizeof(data->otype));

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    bpf_ringbuf_submit(data, 0);
    return 0;
}

#endif