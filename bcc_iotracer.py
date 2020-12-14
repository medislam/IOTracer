#!/usr/bin/python


from bcc import BPF
import ctypes as ct

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

	};

	BPF_PERF_OUTPUT(events);

	

	int generic_file_write_iter_handler(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *from){
		bpf_trace_printk("generic_file_write_iter_handler\\n");
		struct data_log log = {};

		size_t s = iov_iter_count(from);

		log.timestamp = bpf_ktime_get_ns();
		log.address = iocb->ki_pos;
		log.size = from->count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'V';
		log.op  = 'W';

		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}


	int generic_file_read_iter_handler(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *iter){
		bpf_trace_printk("generic_file_read_iter_handler\\n");
		struct data_log log = {};

		log.timestamp = bpf_ktime_get_ns();
		log.address = iocb->ki_pos; 
		log.size = iter->count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'V';
		log.op  = 'R';

		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}


	int generic_make_request_handler(struct pt_regs *ctx, struct bio *bio){
		bpf_trace_printk("generic_make_request_handler\\n");
		struct data_log log = {};

		log.timestamp = bpf_ktime_get_ns();
		log.address = bio->bi_iter.bi_sector; 
		log.size = ((bio->bi_iter).bi_size >> 9) * SECTOR_SIZE;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'B';
		log.op  = (((bio->bi_opf & REQ_OP_MASK)) & 1) ? IO_WRITE_EVENT : IO_READ_EVENT;

		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}

""")


b = BPF(text = program)

# Attach kprobes to the functions 
b.attach_kprobe(event="__generic_file_write_iter", fn_name="generic_file_write_iter_handler")
b.attach_kprobe(event="generic_file_read_iter", fn_name="generic_file_read_iter_handler")
b.attach_kprobe(event="generic_make_request", fn_name="generic_make_request_handler")

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
    log = (evenement.timestamp,evenement.address,evenement.size,evenement.level,evenement.op,evenement.pid,evenement.comm)
    format_ = "%.0f, %.0f, %.0f, %s, %s, %d, %s"
    print(format_ % log)
    #evenement = b["events"].event(data)
    #print("%.0f, %.0f, %.0f, %s, %s, %d, %s" ,evenement.timestamp,evenement.address,evenement.size,evenement.level,evenement.op,evenement.pid,evenement.comm)




b["events"].open_perf_buffer(afficher_evenement)

# print result to user
while 1:
    # read messages from PERF BUFFER and send them to afficher_evenement
    b.perf_buffer_poll()