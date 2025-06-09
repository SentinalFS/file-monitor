# file monitor

It monitors files

## Dir structure

```
.
├── CHANGELOG.json
├── CMakeLists.txt
├── common.h
├── data_types.h
├── headers.h
├── helpers
│   ├── delete.h
│   ├── read_write.h
│   └── rename.h
├── monitor.c
├── README.md
├── VERSION.txt
└── vmlinux.h
```

## BPF traces

### VFS Read

```sh
sudo bpftrace -e 'kprobe:vfs_read { 
    $file = (struct file *)arg0;
    $dentry = $file->f_path.dentry;
    
    if ($dentry != 0) {
        printf("READ - File: %s, Size: %d bytes, PID: %d, Comm: %s\n", 
               str($dentry->d_name.name), 
               arg2,  // count/size parameter
               pid, 
               comm);
               
        $parent = $dentry->d_parent;
        if ($parent != 0) {
            printf("  Parent dir: %s\n", str($parent->d_name.name));
        }
    }
}'
```

### VFS Write

```sh
sudo bpftrace -e 'kprobe:vfs_write { 
    $file = (struct file *)arg0;
    $dentry = $file->f_path.dentry;
    
    if ($dentry != 0) {
        printf("WRITE - File: %s, Size: %d bytes, PID: %d, Comm: %s\n", 
               str($dentry->d_name.name), 
               arg2,  // count/size parameter
               pid, 
               comm);
               
        $parent = $dentry->d_parent;
        if ($parent != 0) {
            printf("  Parent dir: %s\n", str($parent->d_name.name));
        }
    }
}'
```

### VFS Rename

```sh
sudo bpftrace -e 'kprobe:vfs_rename { 
    $old_dentry = (struct dentry *)arg1;
    $new_dentry = (struct dentry *)arg3;
    
    if ($old_dentry != 0 && $new_dentry != 0) {
        printf("RENAME - From: %s, To: %s, PID: %d, Comm: %s\n", 
               str($old_dentry->d_name.name), 
               str($new_dentry->d_name.name),
               pid, 
               comm);
               
        $old_parent = $old_dentry->d_parent;
        $new_parent = $new_dentry->d_parent;
        
        if ($old_parent != 0) {
            printf("  Source dir: %s\n", str($old_parent->d_name.name));
        }
        
        if ($new_parent != 0) {
            printf("  Target dir: %s\n", str($new_parent->d_name.name));
        }
    }
}'
```

### VFS Unlink

```sh
sudo bpftrace -e 'kprobe:vfs_unlink { 
    $dentry = (struct dentry *)arg2;
    printf("dentry ptr: %p, d_name.len: %d, d_name.name_ptr: %s\n", 
    $dentry, $dentry->d_name.len, str($dentry->d_name.name));
    
    $parent = $dentry->d_parent;
    if ($parent != 0) {
        printf("Parent name: %s\n", str($parent->d_name.name));
    } else {
        printf("Parent: NULL\n");
    }
}'
```
