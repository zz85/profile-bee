# Kprobe & Tracepoint Profiling Examples

## Finding available targets

```bash
# Kprobe: any non-static kernel function
cat /proc/kallsyms | grep ' T ' | awk '{print $3}' | head -20

# Tracepoints: predefined stable kernel hooks
sudo ls /sys/kernel/debug/tracing/events/
sudo ls /sys/kernel/debug/tracing/events/syscalls/
```

## Kprobe examples

Kprobes attach to kernel functions dynamically. The actual function name depends on kernel version — check `/proc/kallsyms` if a probe fails to attach.

```bash
# File opens
sudo profile-bee --kprobe do_sys_open --time 3000 --tui

# VFS reads/writes
sudo profile-bee --kprobe vfs_read --time 3000 --tui
sudo profile-bee --kprobe vfs_write --time 3000 --tui

# TCP connections
sudo profile-bee --kprobe tcp_sendmsg --time 3000 --tui
sudo profile-bee --kprobe tcp_v4_connect --time 3000 --tui

# Memory allocation
sudo profile-bee --kprobe __alloc_pages_nodemask --time 3000 --tui

# Process creation
sudo profile-bee --kprobe do_fork --time 3000 --tui

# Context switches
sudo profile-bee --kprobe finish_task_switch --time 2000 --tui
```

## Tracepoint examples

Tracepoints use the format `category:event` and are stable across kernel versions.

```bash
# Syscall entry
sudo profile-bee --tracepoint syscalls:sys_enter_write --time 3000 --tui
sudo profile-bee --tracepoint syscalls:sys_enter_read --time 3000 --tui
sudo profile-bee --tracepoint syscalls:sys_enter_openat --time 3000 --tui

# Scheduler
sudo profile-bee --tracepoint sched:sched_switch --time 3000 --tui
sudo profile-bee --tracepoint sched:sched_wakeup --time 3000 --tui

# Block I/O
sudo profile-bee --tracepoint block:block_rq_issue --time 3000 --tui

# Network
sudo profile-bee --tracepoint tcp:tcp_probe --time 3000 --tui
sudo profile-bee --tracepoint net:net_dev_xmit --time 3000 --tui

# Memory
sudo profile-bee --tracepoint kmem:mm_page_alloc --time 3000 --tui
```
