#include "headers.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct inode_key);
    __type(value, u32);
    __uint(max_entries, 256);
} monitored_inodes SEC(".maps");


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