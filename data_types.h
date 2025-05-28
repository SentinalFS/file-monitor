#include "headers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct inode_key);
    __type(value, u32);
    __uint(max_entries, 256);
} monitored_inodes SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct data_t);
    __uint(max_entries, 1);
} logs_data SEC(".maps");

struct inode_key
{
    u32 inode;
};

struct data_t
{
    u32 pid;
    u32 uid;
    char filename[128];
    char comm[16];
    u64 timestamp;
    char otype[16];
};