#!/usr/bin/python3
#
# vfsreadlat.py		VFS read latency distribution.
#			For Linux, uses BCC, eBPF. See .c file.
#
# Written as a basic example of a function latency distribution histogram.
#
# USAGE: vfsreadlat.py [interval [count]]
#
# The default interval is 5 seconds. A Ctrl-C will print the partially
# gathered histogram then exit.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Aug-2015	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep
from sys import argv

def usage():
	print("USAGE: %s [interval [count]]" % argv[0])
	exit()

# arguments
interval = 5
count = -1
if len(argv) > 1:
	try:
		interval = int(argv[1])
		if interval == 0:
			raise
		if len(argv) > 2:
			count = int(argv[2])
	except:	# also catches -h, --help
		usage()

# load BPF program
a = BPF(src_file = "vfsreadlat.c")
a.attach_kprobe(event="__sys_sendto", fn_name="do_entry")
a.attach_kretprobe(event="__sys_sendto", fn_name="do_return")

b = BPF(src_file = "vfsreadlat.c")
b.attach_kprobe(event="sock_sendmsg", fn_name="do_entry")
b.attach_kretprobe(event="sock_sendmsg", fn_name="do_return")

e = BPF(src_file = "vfsreadlat.c")
e.attach_kprobe(event="security_socket_sendmsg", fn_name="do_entry")
e.attach_kretprobe(event="security_socket_sendmsg", fn_name="do_return")

c = BPF(src_file = "vfsreadlat.c")
c.attach_kprobe(event="xsk_sendmsg", fn_name="do_entry")
c.attach_kretprobe(event="xsk_sendmsg", fn_name="do_return")

# d = BPF(src_file = "vfsreadlat.c")
# d.attach_kprobe(event="xsk_generic_xmit", fn_name="do_entry")
# d.attach_kretprobe(event="xsk_generic_xmit", fn_name="do_return")

# d = BPF(src_file = "vfsreadlat.c")
# d.attach_kprobe(event="xsk_xmit", fn_name="do_entry")
# d.attach_kretprobe(event="xsk_xmit", fn_name="do_return")

f = BPF(src_file = "vfsreadlat.c")
f.attach_kprobe(event="sockfd_lookup_light", fn_name="do_entry")
f.attach_kretprobe(event="sockfd_lookup_light", fn_name="do_return")

g = BPF(src_file = "vfsreadlat.c")
g.attach_kprobe(event="handle_mm_fault", fn_name="do_entry_pg")
# a = BPF(src_file = "vfsreadlat.c")
# a.attach_kprobe(event=a.get_syscall_fnname("getpid"), fn_name="do_entry")
# a.attach_kretprobe(event=a.get_syscall_fnname("getpid"), fn_name="do_return")

# header
print("Tracing... Hit Ctrl-C to end.")

# output
loop = 0
do_exit = 0
while (1):
	if count > 0:
		loop += 1
		if loop > count:
			exit()
	try:
		sleep(interval)
	except KeyboardInterrupt:
		pass; do_exit = 1

	print("systemcall")
	a["dist"].print_log2_hist("usecs")
	a["dist"].clear()

	print("lookup")
	f["dist"].print_log2_hist("usecs")
	f["dist"].clear()

	print("sock send")
	b["dist"].print_log2_hist("usecs")
	b["dist"].clear()

	print("security")
	e["dist"].print_log2_hist("usecs")
	e["dist"].clear()
    
	print("xsk send")
	c["dist"].print_log2_hist("usecs")
	c["dist"].clear()

	print("page fualt")
	print(list(list(g["arr"].items())[0][1]))
	# print(dir(list(g["arr"].items())[0][1]))
	g["arr"].clear()

	# print("netvsc send")
	# d["dist"].print_log2_hist("usecs")
	# d["dist"].clear()

	if do_exit:
		exit()
