import argparse
from datetime import datetime
import os
import ctypes as ct
import subprocess
from bcc import BPF


class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("filename", ct.c_char * 128),
        ("comm", ct.c_char * 16),
        ("timestamp", ct.c_uint64),
        ("otype", ct.c_char * 16),
    ]


def setup_monitoring(bpf, paths):
    monitored_inodes = bpf.get_table("monitored_inodes")
    for path in paths:
        try:
            inode = int(get_inode_from_filepath(path.strip()))
            monitored_inodes[ct.c_uint32(inode)] = ct.c_uint32(inode)
            print(f"Monitoring: {path} (inode={ct.c_uint32(inode)})")
        except FileNotFoundError:
            print(f"File not found: {os.path.abspath(path)}")
        except Exception as e:
            print(f"Error monitoring {os.path.abspath(path)}: {e}")


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    timestamp = datetime.fromtimestamp(event.timestamp / 1e9).strftime("%H:%M:%S")
    print(
        f"[{timestamp}] PID={event.pid}, UID={event.uid}, "
        f"Operation={event.otype.decode()}, File={event.filename.decode()}, "
        f"Process={event.comm.decode()}"
    )


def main():
    parser = argparse.ArgumentParser(description="Monitor file operations using eBPF")
    parser.add_argument("paths", nargs="+", help="Paths to monitor")
    args = parser.parse_args()

    try:
        bpf = BPF(src_file="monitor.c")
        print("eBPF program loaded successfully.")
    except Exception as e:
        print(f"Failed to load eBPF program: {e}")
        exit(1)

    setup_monitoring(bpf, args.paths)

    try:
        bpf.attach_kprobe(event="vfs_read", fn_name="trace_read")
        print("Attached kprobe to vfs_read.")
        bpf.attach_kprobe(event="vfs_write", fn_name="trace_write")
        print("Attached kprobe to vfs_write.")
        bpf.attach_kprobe(event="vfs_rename", fn_name="trace_rename")
        print("Attached kprobe to vfs_rename.")
    except Exception as e:
        print(f"Failed to attach kprobes: {e}")
        exit(1)

    print("Started monitoring... Press Ctrl+C to stop")

    try:
        bpf["events"].open_perf_buffer(print_event)
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error while polling events: {e}")


def get_inode_from_filepath(filepath):
    cmd = f"ls {filepath} 2>&1 1>/dev/null && ls -i {filepath}"
    cmd += " | awk '{print $1}'"
    try:
        output = subprocess.check_output(cmd, shell=True)
        output = output.decode()
        return output.split("\n")[0]
    except:  # noqa: E722
        return ""


if __name__ == "__main__":
    main()