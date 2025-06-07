#ifndef DELETE_H
#define DELETE_H

#include "../headers.h"
#include "../data_types.h" // Make sure this is included for data_t and events

static __always_inline int trace_file_delete(struct pt_regs *ctx, struct dentry *dentry, const char *operation)
{
    if (!dentry)
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
    bpf_core_read(&d_name_qstr, sizeof(d_name_qstr), &dentry->d_name);
    if (d_name_qstr.len < 0)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    char fname[FILE_NAME_SIZE] = {};
    bpf_core_read_str(fname, sizeof(fname), d_name_qstr.name);

    bpf_trace_printk("Raw filename attempt: %s\n", sizeof("Raw filename attempt: %s\n"), fname);
    __builtin_memcpy(data->filename, fname, sizeof(data->filename));
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid(); // Reads current UID
    data->timestamp = bpf_ktime_get_ns();

    if (bpf_probe_read_kernel_str(data->otype, sizeof(data->otype), operation) < 0)
    {
        const char err_op[] = "[OP_READ_ERR]";
        __builtin_memcpy(data->otype, err_op, sizeof(err_op));
    }
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    bpf_ringbuf_submit(data, 0);
    return 0;
}

#endif