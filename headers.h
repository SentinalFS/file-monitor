#ifndef MY_HEADER_H
#define MY_HEADER_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define FILE_NAME_SIZE 144
#define OTYPE_SIZE 16
#define COMM_SIZE 32
#define DCACHE_NEGATIVE_DENTRY 0x0020

#endif