#ifndef RENAME_H
#define RENAME_H

#include "../headers.h"
#include "../data_types.h"

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

    struct qstr old_name = {};
    bpf_core_read(&old_name, sizeof(old_name), &old_dentry->d_name);
    if (old_name.len == 0)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    struct qstr new_name = {};
    bpf_core_read(&new_name, sizeof(new_name), &new_dentry->d_name);
    if (new_name.len == 0)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    char OPRN[] = "RENAME";
    char old_fname[FILE_NAME_SIZE] = {};
    char new_fname[FILE_NAME_SIZE] = {};
    bpf_core_read_str(old_fname, sizeof(old_fname), old_name.name);
    bpf_core_read_str(new_fname, sizeof(new_fname), new_name.name);

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->timestamp = bpf_ktime_get_ns();

    __builtin_memcpy(data->old_filename, old_fname, sizeof(data->old_filename));
    __builtin_memcpy(data->new_filename, new_fname, sizeof(data->new_filename));
    __builtin_memcpy(data->otype, OPRN, sizeof(data->otype));
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    bpf_trace_printk("LOG: old_filename=%s new_filename=%s otype=%s comm=%s\n",
                     sizeof("LOG: old_filename=%s new_filename=%s otype=%s comm=%s\n"),
                     data->old_filename, data->new_filename, data->otype);
    bpf_trace_printk("LOG: comm=%s\n", sizeof("LOG: comm=%s\n"), data->comm);
    bpf_trace_printk("LOG: old_name=%s new_name=%s\n",
                     sizeof("LOG: old_name=%s new_name=%s\n"),
                     old_fname, new_fname);

    bpf_ringbuf_submit(data, 0);

    return 0;
}

#endif