#ifndef DELETE_H
#define DELETE_H

#include "../headers.h"
#include "../data_types.h"

static __always_inline int trace_file_delete(struct pt_regs *ctx, struct dentry *de)
{
    if (!de)
    {
        bpf_trace_printk("trace_file_delete: dentry is NULL\n", sizeof("trace_file_delete: dentry is NULL\n"));
        return 0;
    }

    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data)
    {
        bpf_trace_printk("trace_file_delete: failed to reserve ringbuf\n", sizeof("trace_file_delete: failed to reserve ringbuf\n"));
        return 0;
    }
    __builtin_memset(data, 0, sizeof(*data));

    struct qstr d_name_qstr = {};
    bpf_core_read(&d_name_qstr, sizeof(d_name_qstr), &de->d_name);

    if (d_name_qstr.len <= 0 || !d_name_qstr.name || d_name_qstr.name == (void *)-1UL || d_name_qstr.name == NULL)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    unsigned char d_flags = 0;
    bpf_core_read(&d_flags, sizeof(d_flags), &de->d_flags);
    if (d_flags & DCACHE_NEGATIVE_DENTRY) {
        bpf_trace_printk("trace_file_delete: negative dentry detected (file likely non-existent). Discarding.\n", sizeof("trace_file_delete: negative dentry detected (file likely non-existent). Discarding.\n"));
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    char fname[FILE_NAME_SIZE] = {};
    bpf_core_read_str(fname, sizeof(fname), d_name_qstr.name);

    char OPRN[] = "DELETE";
    __builtin_memcpy(data->filename, fname, sizeof(data->filename));
    __builtin_memcpy(data->otype, OPRN, sizeof(data->otype));
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    int cgroup_id = bpf_get_current_cgroup_id();
    data->cgroup_id = cgroup_id;

    bpf_ringbuf_submit(data, 0);
    return 0;
}

#endif