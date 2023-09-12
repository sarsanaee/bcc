/* SPDX-License-Identifier: GPL-2.0 */

#include <uapi/linux/ptrace.h>
// #include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

BPF_HASH(start, u32);
BPF_HISTOGRAM(dist);
BPF_PERCPU_ARRAY(arr, u64, 1);

int do_entry_pg(struct pt_regs *ctx)
{
	u32 pid;
    u32 index = 0;
    u64 *val;

	val = arr.lookup(&index);

    if (val) {
        *val = *val+1;
    }

	return 0;
}

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
		dist.increment(bpf_log2l(delta / 1000));
		start.delete(&pid);
	}

	return 0;
}


// char LICENSE[] SEC("license") = "GPL";
