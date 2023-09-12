#!/usr/bin/python3
#
# This is a Hello World example that formats output as fields.

from bcc import BPF
from bcc.utils import printb
import math

# define BPF program

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <linux/skbuff.h>

struct two_st {
    uint64_t test;
    struct bpf_spin_lock lock;
};

// BPF_PERCPU_ARRAY(counts, struct two_st, 32);
BPF_PERCPU_ARRAY(counts, u64, 32);
BPF_HASH(start, u32);

int do_entry(struct pt_regs *ctx)
{
    u32 pid;
    u64 ts;

    pid = bpf_get_current_pid_tgid();
    ts = bpf_ktime_get_ns();

    start.update(&pid, &ts);

    return 0;
}

int do_return(struct pt_regs *ctx)
{
    u32 pid;
    u64 *tsp, delta;

    pid = bpf_get_current_pid_tgid();
    tsp = start.lookup(&pid);

    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta > 15000) {
            bpf_trace_printk("long runtime %lu\\n", delta);
        }
        start.delete(&pid);
    }

    return 0;
}


int sys_send_to_start(void *ctx) {
    bpf_trace_printk("start syscall %lu\\n", bpf_ktime_get_ns());
    return 0;
}

int sys_send_to_end(void *ctx) {
    bpf_trace_printk("end syscall %lu\\n", bpf_ktime_get_ns());
    return 0;
}

int sys_sock_send_to_start(void *ctx) {
    bpf_trace_printk("start sock %lu\\n", bpf_ktime_get_ns());
    return 0;
}

int sys_sock_send_to_end(void *ctx) {
    bpf_trace_printk("end sock %lu\\n", bpf_ktime_get_ns());
    return 0;
}

int sys_xsk_send_to_start(void *ctx) {
    bpf_trace_printk("start xsk %lu\\n", bpf_ktime_get_ns());
    return 0;
}

int sys_xsk_send_to_end(void *ctx) {
    bpf_trace_printk("end xsk %lu\\n", bpf_ktime_get_ns());
    return 0;
}

int sys_driver_send_to_start(void *ctx) {
    bpf_trace_printk("start driver %lu\\n", bpf_ktime_get_ns());
    return 0;
}

int sys_driver_send_to_end(void *ctx) {
    bpf_trace_printk("end driver %lu\\n", bpf_ktime_get_ns());
    return 0;
}

int just_checking(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}

int hello(struct pt_regs *ctx, struct socket *sock, struct msghdr *m, size_t len) {
    uint64_t ts = bpf_ktime_get_ns();
    int key = 0;
    counts.update(&key, &ts);
    // bpf_trace_printk("hello %lu\\n", len);
    return 0;
}

int test(struct pt_regs *ctx, struct sk_buff *skb) {
    int ret = PT_REGS_RC(ctx);
    if (ret != 0)
        return 0;
    // uint64_t ts1 = bpf_ktime_get_ns();
    int key = 0;
    unsigned char * data = skb->data;
    uint64_t* tx_burst = (uint64_t*)(data+20+14+8+30+4*8);
    uint64_t stack_data = *tx_burst;
    // int diff = ts1 - *tx_burst;
    // *tx_burst = diff;
    // if (diff > 0)
    // if (skb->len > 80 && diff > 10000)
    // if (skb->len > 80)
    // bpf_trace_printk("bye %d\\n", diff); 
    counts.update(&key, &stack_data);
    // }
    return 0;
}

int first(struct pt_regs *ctx, struct sk_buff *skb) {
    int key = 0;
    unsigned char * data = skb->data;
    uint64_t* tx_burst = (uint64_t*)(data+20+14+8+30+4*8);
    uint64_t stack_data = *tx_burst;
    if (skb->len > 80)
        counts.update(&key, &stack_data);
    else {
        stack_data = 0;
        counts.update(&key, &stack_data);
    }
    return 0;
}

int bye(struct pt_regs *ctx, struct sk_buff *skb) {
    int ret = PT_REGS_RC(ctx);
    if (ret != 0)
        return 0;
    uint64_t ts1 = bpf_ktime_get_ns();
    int key = 0;
    uint64_t * value = counts.lookup(&key);
    if (value && *value!=0) {
        int diff = ts1 - *value;
        // if (diff > 10000)
        bpf_trace_printk("bye %d\\n", diff); 
    }
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
# b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
# b.attach_kprobe(event=b.get_syscall_fnname(""), fn_name="just_checking")
# b.attach_kprobe(event="sendmsg", fn_name="just_checking")

b.attach_kprobe(event="__sys_sendto", fn_name="do_entry")
b.attach_kretprobe(event="__sys_sendto", fn_name="do_return")

# b.attach_kprobe(event="xsk_sendmsg", fn_name="sys_xsk_send_to_start")
# b.attach_kretprobe(event="xsk_sendmsg", fn_name="sys_xsk_send_to_end")
# 
# b.attach_kprobe(event="sock_sendmsg", fn_name="sys_sock_send_to_start")
# b.attach_kretprobe(event="sock_sendmsg", fn_name="sys_sock_send_to_end")
# 
# b.attach_kprobe(event="xsk_generic_xmit", fn_name="sys_driver_send_to_start")
# b.attach_kretprobe(event="xsk_generic_xmit", fn_name="sys_driver_send_to_end")

# b.attach_kprobe(event="sendmsg_unlocked", fn_name="just_checking")
# b.attach_kprobe(event="netvsc_poll", fn_name="hello")
# b.attach_kprobe(event="xsk_generic_xmit", fn_name="hello")
# b.attach_kprobe(event="__dev_direct_xmit", fn_name="first")
# b.attach_kretprobe(event="__dev_direct_xmit", fn_name="bye")
# b.attach_kprobe(event="netvsc_send_pkt", fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

data = []
counter = 0
# format output

def percentile():
   data.sort() 
   index50 = 50*(len(data))//100
   index99 = 99*(len(data))//100
   index999 = math.floor((99.9*(len(data)))//100)
   return (data[index50], data[index99], data[index999], sum(data)/len(data))
   

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        # data.append(int(msg.decode().split(" ")[1]))
    except ValueError:
        continue
    except KeyboardInterrupt:
        # print(percentile())
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
    # counter += 1
    # if (counter > 1000000):
    #     print(percentile())
    #     break
