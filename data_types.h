#ifndef DATA_TYPES_H
#define DATA_TYPES_H

#include "headers.h"

// Lets match parent/filename & inode with data in crds

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rename_events SEC(".maps");

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
    u64 inode;
    char parent_filename[FILE_NAME_SIZE];
    char filename[FILE_NAME_SIZE];
    char comm[COMM_SIZE];
    u64 timestamp;
    u64 cgroup_id;
    char otype[OTYPE_SIZE];
};

struct rename_data_t
{
    u32 pid;
    u32 uid;
    u32 inode_old;
    u32 inode_new;
    char new_parent_filename[FILE_NAME_SIZE];
    char old_parent_filename[FILE_NAME_SIZE];
    char old_filename[FILE_NAME_SIZE];
    char new_filename[FILE_NAME_SIZE];
    char comm[COMM_SIZE];
    u64 timestamp;
    u64 cgroup_id;
    char otype[OTYPE_SIZE];
};

#endif