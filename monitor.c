// SPDX-License-Identifier: GPL-2.0
#include "headers.h"
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

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
    struct dentry *old_dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    struct dentry *new_dentry = (struct dentry *)PT_REGS_PARM4(ctx);

    return trace_file_rename(ctx, old_dentry, new_dentry);
}

SEC("kprobe/vfs_unlink")
int trace_delete(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);

    char OPRN[] = "DELETE";
    return trace_file_delete(ctx, dentry, OPRN);
}