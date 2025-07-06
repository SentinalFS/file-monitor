#ifndef RENAME_H
#define RENAME_H

#include "../headers.h"
#include "../data_types.h"
#include "../utils/utils.h"

static __always_inline int trace_file_rename(
    struct pt_regs *ctx, struct dentry *old_dentry, struct dentry *new_dentry)
{
    if (!old_dentry || !new_dentry)
        return 0;

    struct rename_data_t *data = bpf_ringbuf_reserve(&rename_events, sizeof(struct rename_data_t), 0);
    if (!data)
    {
        return 0;
    }
    __builtin_memset(data, 0, sizeof(*data));

    char OPRN[] = "RENAME";

    // Read old filename from dentry
    struct qstr old_name = {};
    bpf_core_read(&old_name, sizeof(old_name), &old_dentry->d_name);
    if (old_name.len == 0)
    {
        DISCARD_AND_RETURN(data);
    }

    // Read new filename from dentry
    struct qstr new_name = {};
    bpf_core_read(&new_name, sizeof(new_name), &new_dentry->d_name);
    if (new_name.len == 0)
    {
        DISCARD_AND_RETURN(data);
    }

    // Get old parent dentry
    struct dentry *old_parent_de = NULL;
    bpf_core_read(&old_parent_de, sizeof(old_parent_de), &old_dentry->d_parent);
    if (!old_parent_de)
    {
        DISCARD_AND_RETURN(data);
    }

    // Get new parent dentry
    struct dentry *new_parent_de = NULL;
    bpf_core_read(&new_parent_de, sizeof(new_parent_de), &new_dentry->d_parent);
    if (!new_parent_de)
    {
        DISCARD_AND_RETURN(data);
    }

    // Check for negative dentries in old parent and new parent
    unsigned char old_parent_flags = 0;
    unsigned char new_parent_flags = 0;
    bpf_core_read(&new_parent_flags, sizeof(new_parent_flags), &new_parent_de->d_flags);
    bpf_core_read(&old_parent_flags, sizeof(old_parent_flags), &old_parent_de->d_flags);
    if ((old_parent_flags & DCACHE_NEGATIVE_DENTRY) || (new_parent_flags & DCACHE_NEGATIVE_DENTRY)) {
        DISCARD_AND_RETURN(data);
    }

    // Read old parent filename from old parent dentry
    struct qstr old_parent_name = {};
    bpf_core_read(&old_parent_name, sizeof(old_parent_name), &old_parent_de->d_name);
    if (old_parent_name.len == 0)
    {
        DISCARD_AND_RETURN(data);
    }

    // Read new parent filename from new parent dentry
    struct qstr new_parent_name = {};
    bpf_core_read(&new_parent_name, sizeof(new_parent_name), &new_parent_de->d_name);
    if (new_parent_name.len == 0)
    {
        DISCARD_AND_RETURN(data);
    }

    // Get inode number for old dentry
    struct inode *old_inode_ptr = NULL;
    bpf_core_read(&old_inode_ptr, sizeof(old_inode_ptr), &old_dentry->d_inode);
    if (old_inode_ptr)
        bpf_core_read(&data->inode_old, sizeof(data->inode_old), &old_inode_ptr->i_ino);
    else
        data->inode_old = NEGATIVE_INODE_NUMBER;

    // Get inode number for new dentry
    struct inode *new_inode_ptr = NULL;
    bpf_core_read(&new_inode_ptr, sizeof(new_inode_ptr), &new_dentry->d_inode);
    if (new_inode_ptr)
        bpf_core_read(&data->inode_new, sizeof(data->inode_new), &new_inode_ptr->i_ino);
    else
        data->inode_new = NEGATIVE_INODE_NUMBER;

    // Get cgroup ID
    int cgroup_id = bpf_get_current_cgroup_id();

    // Copy data into the data structure
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->timestamp = bpf_ktime_get_ns();
    data->cgroup_id = cgroup_id;

    bpf_core_read_str(data->old_filename, sizeof(data->old_filename), old_name.name);
    bpf_core_read_str(data->new_filename, sizeof(data->new_filename), new_name.name);
    bpf_core_read_str(data->old_parent_filename, sizeof(data->old_parent_filename), old_parent_name.name);
    bpf_core_read_str(data->new_parent_filename, sizeof(data->new_parent_filename), new_parent_name.name);
    __builtin_memcpy(data->otype, OPRN, sizeof(data->otype));

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    bpf_trace_printk("LOG: old_filename=%s new_filename=%s otype=%s comm=%s\n", sizeof("LOG: old_filename=%s new_filename=%s otype=%s comm=%s\n"), data->old_filename, data->new_filename, data->otype);
    bpf_trace_printk("LOG: comm=%s\n", sizeof("LOG: comm=%s\n"), data->comm);
    bpf_trace_printk("LOG: old_name=%s new_name=%s\n", sizeof("LOG: old_name=%s new_name=%s\n"), data->old_filename, data->new_filename);

    bpf_ringbuf_submit(data, 0);

    return 0;
}

#endif