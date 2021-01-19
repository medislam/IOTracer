#!/usr/bin/python


from bcc import BPF
import ctypes as ct

import argparse
import sys 
from subprocess import check_output 


# arguments
examples ="""
	./bcc_iotracer.py -t task_name -i file_inode # trace task task_pid I/O on file inode file_inode
"""


parser = argparse.ArgumentParser(
    description="Trace VFS and Block I/O",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-t", "--task",
    help="trace this task only")

parser.add_argument("-i", "--inode",
    help="trace this inode only")

args = parser.parse_args()
name = args.task
inode = args.inode

pid = int(check_output(["pidof","-s",name]))


print("task pid = ",pid , "task name", name, "inode = ",inode)



# Define eBPF program
program=("""

	#include <linux/fs.h>
	#include <linux/aio.h>
	#include <linux/uio.h>

	#include <linux/bio.h>
	#include <linux/blk_types.h>
	#include <linux/genhd.h>

	#include <linux/sched.h>

	#define IO_READ_EVENT  ('R')
	#define IO_WRITE_EVENT ('W')

	#define SECTOR_SIZE 512

	struct data_log{
    	u64 	timestamp;
    	u64 	address;
    	u64		size;
    	int 	pid;
    	char 	level;
    	char 	op;
    	char comm[16];
    	char probe;

	};

	BPF_PERF_OUTPUT(events);

	ssize_t VFS_write_handler(struct pt_regs *ctx,struct file * file, const char __user * buf, size_t count, loff_t * pos){
		bpf_trace_printk("VFS_write_handler\\n");


		int pid = bpf_get_current_pid_tgid();

		if(FILTER_PID)
			return 0;


		struct data_log log = {};
		log.timestamp = bpf_ktime_get_ns();

		log.address = file->f_pos;	
		log.size = count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'V';
		log.op  = 'W';

		log.probe = 'G';

		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}


	ssize_t VFS_read_handler(struct pt_regs *ctx,struct file * file, const char __user * buf, size_t count, loff_t * pos){
		bpf_trace_printk("VFS_write_handler\\n");


		int pid = bpf_get_current_pid_tgid();

		if(FILTER_PID)
			return 0;


		struct data_log log = {};
		log.timestamp = bpf_ktime_get_ns();

		log.address = file->f_pos;	
		log.size = count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'V';
		log.op  = 'R';

		log.probe = 'H';

		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}



	ssize_t generic_perform_write_handler(struct pt_regs *ctx,struct file *file, struct iov_iter *i, loff_t pos){
		bpf_trace_printk("generic_file_write_iter_handler\\n");


		int pid = bpf_get_current_pid_tgid();

		if(FILTER_PID)
			return 0;


		struct data_log log = {};
		log.timestamp = bpf_ktime_get_ns();

		log.address = file->f_pos;	
		log.size = i->count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'V';
		log.op  = 'W';

		log.probe = 'A';

		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}



	int generic_file_write_iter_handler(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *from){
		bpf_trace_printk("generic_file_write_iter_handler\\n");
		
		int pid = bpf_get_current_pid_tgid();

		if(FILTER_PID)
			return 0;


		struct data_log log = {};

		size_t s = iov_iter_count(from);

		log.timestamp = bpf_ktime_get_ns();
		log.address = iocb->ki_pos;
		log.size = from->count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'V';
		log.op  = 'W';

		log.probe = 'B';

		


		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}


	int generic_file_read_iter_handler(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *iter){
		bpf_trace_printk("generic_file_read_iter_handler\\n");
		
		int pid = bpf_get_current_pid_tgid();

		if(FILTER_PID)
			return 0;


		struct data_log log = {};

		log.timestamp = bpf_ktime_get_ns();
		log.address = iocb->ki_pos; 
		log.size = iter->count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'V';
		log.op  = 'R';

		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		log.probe = 'C';

		


		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}


	int submit_bio_handler(struct pt_regs *ctx, struct bio *bio){
		bpf_trace_printk("submit_bio_handler\\n");

		int pid = bpf_get_current_pid_tgid();

		if(FILTER_PID)
			return 0;


		struct data_log log = {};

		log.timestamp = bpf_ktime_get_ns();
		log.address = bio->bi_iter.bi_sector; 
		log.size = ((bio->bi_iter).bi_size >> 9) * SECTOR_SIZE;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'B';
		log.op  = (((bio->bi_opf & REQ_OP_MASK)) & 1) ? IO_WRITE_EVENT : IO_READ_EVENT;

		log.probe = 'D';

		


		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}

	int submit_bio_noacct_handler(struct pt_regs *ctx, struct bio *bio){
		bpf_trace_printk("submit_bio_handler\\n");

		int pid = bpf_get_current_pid_tgid();

		if(FILTER_PID)
			return 0;


		struct data_log log = {};

		log.timestamp = bpf_ktime_get_ns();
		log.address = bio->bi_iter.bi_sector; 
		log.size = ((bio->bi_iter).bi_size >> 9) * SECTOR_SIZE;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'B';
		log.op  = (((bio->bi_opf & REQ_OP_MASK)) & 1) ? IO_WRITE_EVENT : IO_READ_EVENT;

		log.probe = 'E';

		
		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}


	int bio_endio_handler(struct pt_regs *ctx, struct bio *bio){
		bpf_trace_printk("bio_endio\\n");

		int pid = bpf_get_current_pid_tgid();

		if(FILTER_PID)
			return 0;

		struct data_log log = {};

		log.timestamp = bpf_ktime_get_ns();
		log.address = bio->bi_iter.bi_sector; 
		log.size = ((bio->bi_iter).bi_size >> 9) * SECTOR_SIZE;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'B';
		log.op  = (((bio->bi_opf & REQ_OP_MASK)) & 1) ? IO_WRITE_EVENT : IO_READ_EVENT;

		log.probe = 'F';
		
		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}

""")


# code replacements

if args.task:
    program = program.replace('FILTER_PID', 'pid != %s' % pid)

else:
    print("we must specify the traced pid")
    sys.exit()

if args.inode:
    program = program.replace('FILTER_INODE', 'i_ino != %s' % args.inode)

else:
    print("we must specify the traced inode")
    sys.exit()


b = BPF(text = program)

# Attach kprobes to the functions 
b.attach_kprobe(event="vfs_write", fn_name="VFS_write_handler")
b.attach_kprobe(event="vfs_read", fn_name="VFS_read_handler")
b.attach_kprobe(event="generic_perform_write", fn_name="generic_perform_write_handler")
b.attach_kprobe(event="__generic_file_write_iter", fn_name="generic_file_write_iter_handler")
b.attach_kprobe(event="generic_file_read_iter", fn_name="generic_file_read_iter_handler")
b.attach_kprobe(event="submit_bio", fn_name="submit_bio_handler")
b.attach_kprobe(event="submit_bio_noacct", fn_name="submit_bio_noacct_handler")
b.attach_kprobe(event="bio_endio", fn_name="bio_endio_handler")

#class Data(ct.Structure):
    #_fields_ = [("timestamp", ct.c_ulonglong),("address", ct.c_ulonglong), ("size", ct.c_ulonglong), ("pid", ct.c_int), \
    #("level", ct.c_char), ("op", ct.c_char), ("comm", ct.c_char_p)]


# ------------------ Report traces to user -----------------------
# -------------------------------------------------------------------------
print("Pour stopper eBPF ..... Ctrl+C")

# afficher_evenement parses messages received from perf_buffer_poll
def afficher_evenement(cpu, data, size):
    #evenement = ct.cast(data, ct.POINTER(Data)).contents
    evenement = b["events"].event(data)	
    log = (evenement.timestamp,evenement.address,evenement.size,evenement.level,evenement.op,evenement.pid,evenement.comm, evenement.probe)
    format_ = "%.0f, %.0f, %.0f, %s, %s, %d, %s, %s"
    print(format_ % log)
    #evenement = b["events"].event(data)
    #print("%.0f, %.0f, %.0f, %s, %s, %d, %s" ,evenement.timestamp,evenement.address,evenement.size,evenement.level,evenement.op,evenement.pid,evenement.comm)




b["events"].open_perf_buffer(afficher_evenement)

# print result to user
while 1:
    # read messages from PERF BUFFER and send them to afficher_evenement
    b.perf_buffer_poll()
