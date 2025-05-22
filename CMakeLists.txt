cmake_minimum_required(VERSION 3.13)
project(file_monitor_bpf C)

set(BPF_CLANG clang)
set(BPF_CFLAGS -O2 -g -target bpf -D__TARGET_ARCH_x86)
set(BPF_SRC monitor.c)
set(BPF_OBJ ${CMAKE_BINARY_DIR}/monitor.bpf.o)
set(VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h)

add_custom_command(
    OUTPUT ${VMLINUX_H}
    COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}
    COMMENT "Generating vmlinux.h from kernel BTF"
)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    DEPENDS ${BPF_SRC} ${VMLINUX_H}
    COMMAND ${BPF_CLANG} ${BPF_CFLAGS} -c ${BPF_SRC} -o ${BPF_OBJ}
    COMMENT "Compiling eBPF object"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(all_bpf DEPENDS ${BPF_OBJ})

add_custom_target(clean_bpf
    COMMAND ${CMAKE_COMMAND} -E rm -f ${BPF_OBJ} ${VMLINUX_H}
    COMMENT "Cleaning build artifacts"
)