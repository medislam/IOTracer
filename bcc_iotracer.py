#!/usr/bin/python


from bcc import BPF
import ctypes as ct

import argparse
import sys 
from subprocess import check_output 


# arguments
examples ="""
	./bcc_iotracer.py -t task_name -f -d -i inode 
	# trace task (specified by its pid) I/O on a dir/file inode. if dir is chosen, no recusivity is done
"""


parser = argparse.ArgumentParser(
    description="Trace VFS and Block I/O",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-t", "--task",
    help="trace this task only")

parser.add_argument("-f","--file", action="store_true",
    help="trace only this file")

parser.add_argument("-d","--dir", action="store_true",
    help="trace all files of this directory, recursiviy is not allowed")

parser.add_argument("-i", "--inode",
    help="trace this file inode or all children files inode")

args = parser.parse_args()
name = args.task
inode = args.inode

#print("task task_name:",name)

#pid = int(check_output(["pidof","-s",name]))
pid=-1

#print("task pid = ",pid , "task name", name, "inode = ",inode)



# Define eBPF program
program=("""

	#include <linux/fs.h>
	#include <linux/aio.h>
	#include <linux/uio.h>

	#include <linux/bio.h>
	#include <linux/blk_types.h>
	#include <linux/genhd.h>

	#include <linux/dcache.h> 
 	#include <linux/path.h>

	#include <linux/sched.h>

	#include <linux/mm.h>

	#include <linux/file.h>

	#define DIO_PAGES		64

	#define IO_READ_EVENT  ('R')
	#define IO_WRITE_EVENT ('W')

	#define SECTOR_SIZE 512

	struct dio {
		int flags;			/* doesn't change */
		int op;
		int op_flags;
		blk_qc_t bio_cookie;
		struct gendisk *bio_disk;
		struct inode *inode;
		loff_t i_size;			/* i_size when submitted */
		dio_iodone_t *end_io;		/* IO completion function */

		void *private;			/* copy from map_bh.b_private */

		/* BIO completion state */
		spinlock_t bio_lock;		/* protects BIO fields below */
		int page_errors;		/* errno from get_user_pages() */
		int is_async;			/* is IO async ? */
		bool defer_completion;		/* defer AIO completion to workqueue? */
		bool should_dirty;		/* if pages should be dirtied */
		int io_error;			/* IO error in completion path */
		unsigned long refcount;		/* direct_io_worker() and bios */
		struct bio *bio_list;		/* singly linked via bi_private */
		struct task_struct *waiter;	/* waiting task (NULL if none) */

		/* AIO related stuff */
		struct kiocb *iocb;		/* kiocb */
		ssize_t result;                 /* IO result */

		/*
		 * pages[] (and any fields placed after it) are not zeroed out at
		 * allocation time.  Don't add new fields after pages[] unless you
		 * wish that they not be zeroed.
		 */
		union {
			struct page *pages[DIO_PAGES];	/* page buffer */
			struct work_struct complete_work;/* deferred AIO completion */
		};
	};

	struct data_log{
    	u64 	timestamp;
    	u64 	address;
    	u64		size;
    	int 	pid;
    	char 	level;
    	char 	op;
    	char 	comm[50];
    	char 	probe;
    	u32 	inode;
    	u32 	inodep;

	};

	BPF_PERF_OUTPUT(events);

	ssize_t VFS_write_handler(struct pt_regs *ctx,struct file * file, const char __user * buf, size_t count, loff_t * pos){
		bpf_trace_printk("VFS_write_handler\\n");

		unsigned long i_ino  = file->f_inode->i_ino;

		int pid = bpf_get_current_pid_tgid();

		char 	comm2[50];
		char comm1[50] = "FILTER_CMD";

		bpf_get_current_comm(&comm2, sizeof(comm2));


		for (int i = 0; i < sizeof(comm1); ++i)
    		if (comm1[i] != comm2[i])
    			return 0;

		//if(FILTER_PID)
			//return 0;
		
		if(FILTER_FILE)
			return 0;

		unsigned long i_inop = file->f_path.dentry->d_parent->d_inode->i_ino;


		if(FILTER_DIR)
			return 0;


		struct data_log log = {};
		log.timestamp = bpf_ktime_get_ns();
		log.address = file->f_pos;	
		log.size = count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'V';
		log.op  = 'W';
		log.probe = '1';
		log.inode = i_ino;
		log.inodep = i_inop;
		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}


	ssize_t VFS_read_handler(struct pt_regs *ctx,struct file * file, const char __user * buf, size_t count, loff_t * pos){
		bpf_trace_printk("VFS_write_handler\\n");

		
		unsigned long i_ino  = file->f_inode->i_ino;

		int pid = bpf_get_current_pid_tgid();

		char 	comm2[50];
		char comm1[50] = "FILTER_CMD";

		bpf_get_current_comm(&comm2, sizeof(comm2));


		for (int i = 0; i < sizeof(comm1); ++i)
    		if (comm1[i] != comm2[i])
    			return 0;

		//if(FILTER_PID)
			//return 0;
		
		if(FILTER_FILE)
			return 0;

		unsigned long i_inop = file->f_path.dentry->d_parent->d_inode->i_ino;


		if(FILTER_DIR)
			return 0;

		struct data_log log = {};
		log.timestamp = bpf_ktime_get_ns();
		log.address = file->f_pos;	
		log.size = count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'V';
		log.op  = 'R';
		log.probe = '2';
		log.inode = i_ino;
		log.inodep = i_inop;
		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}


	int generic_file_write_iter_handler(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *from){
		bpf_trace_printk("generic_file_write_iter_handler\\n");
		unsigned long i_ino  = iocb->ki_filp->f_inode->i_ino;
		int pid = bpf_get_current_pid_tgid();

		char 	comm2[50];
		char comm1[50] = "FILTER_CMD";
		bpf_get_current_comm(&comm2, sizeof(comm2));
		for (int i = 0; i < sizeof(comm1); ++i)
    		if (comm1[i] != comm2[i])

    			return 0;
		//if(FILTER_PID)
			//return 0;
		
		if(FILTER_FILE)
			return 0;
		unsigned long i_inop = iocb->ki_filp->f_path.dentry->d_parent->d_inode->i_ino;

		if(FILTER_DIR)
			return 0;
		struct data_log log = {};
		size_t s = iov_iter_count(from);
		log.timestamp = bpf_ktime_get_ns();
		log.address = iocb->ki_pos;
		log.size = from->count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'V';
		log.op  = 'W';
		log.probe = '7';
		
		log.inode = i_ino;
		log.inodep = i_inop;
		bpf_get_current_comm(&log.comm, sizeof(log.comm));
		events.perf_submit(ctx, &log, sizeof(log));
		return 0;
	}


	int generic_file_read_iter_handler(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *iter){
		bpf_trace_printk("generic_file_read_iter_handler\\n");
		unsigned long i_ino  = iocb->ki_filp->f_inode->i_ino;
		int pid = bpf_get_current_pid_tgid();
		char 	comm2[50];
		char comm1[50] = "FILTER_CMD";
		bpf_get_current_comm(&comm2, sizeof(comm2));
		for (int i = 0; i < sizeof(comm1); ++i)
    		if (comm1[i] != comm2[i])
    			return 0;
		//if(FILTER_PID)
			//return 0;
		
		if(FILTER_FILE)
			return 0;
		unsigned long i_inop = iocb->ki_filp->f_path.dentry->d_parent->d_inode->i_ino;
		if(FILTER_DIR)
			return 0;
		struct data_log log = {};
		log.timestamp = bpf_ktime_get_ns();
		log.address = iocb->ki_pos; 
		log.size = iter->count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'V';
		log.op  = 'R';
		bpf_get_current_comm(&log.comm, sizeof(log.comm));
		log.probe = '9';
		
		log.inode = i_ino;
		log.inodep = i_inop;
		events.perf_submit(ctx, &log, sizeof(log));
		return 0;
	}


	ssize_t ext4_file_write_iter_handler(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *from){
		bpf_trace_printk("ext4_file_write_iter_handler\\n");

		unsigned long i_ino  = iocb->ki_filp->f_inode->i_ino;

		int pid = bpf_get_current_pid_tgid();

		char 	comm2[50];
		char comm1[50] = "FILTER_CMD";

		bpf_get_current_comm(&comm2, sizeof(comm2));


		for (int i = 0; i < sizeof(comm1); ++i)
    		if (comm1[i] != comm2[i])
    			return 0;

		//if(FILTER_PID)
			//return 0;
		
		if(FILTER_FILE)
			return 0;

		unsigned long i_inop = iocb->ki_filp->f_path.dentry->d_parent->d_inode->i_ino;

		if(FILTER_DIR)
			return 0;


		struct data_log log = {};

		size_t s = iov_iter_count(from);

		log.timestamp = bpf_ktime_get_ns();
		log.address = iocb->ki_pos;
		log.size = from->count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'F';
		log.op  = 'W';

		log.probe = '4';

		
		log.inode = i_ino;
		log.inodep = i_inop;

		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}


	ssize_t ext4_file_read_iter_handler(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *to){
		bpf_trace_printk("generic_file_read_iter_handler\\n");

		unsigned long i_ino  = iocb->ki_filp->f_inode->i_ino;

		int pid = bpf_get_current_pid_tgid();

		char 	comm2[50];
		char comm1[50] = "FILTER_CMD";

		bpf_get_current_comm(&comm2, sizeof(comm2));


		for (int i = 0; i < sizeof(comm1); ++i)
    		if (comm1[i] != comm2[i])
    			return 0;

		//if(FILTER_PID)
			//return 0;
		
		if(FILTER_FILE)
			return 0;

		unsigned long i_inop = iocb->ki_filp->f_path.dentry->d_parent->d_inode->i_ino;

		//if(FILTER_DIR)
			//return 0;


		struct data_log log = {};

		log.timestamp = bpf_ktime_get_ns();
		log.address = iocb->ki_pos; 
		log.size = to->count;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'F';
		log.op  = 'R';

		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		log.probe = '5';

		
		log.inode = i_ino;
		log.inodep = i_inop;

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}


	int submit_bio_handler(struct pt_regs *ctx, struct bio *bio){
		bpf_trace_printk("submit_bio_handler\\n");

		struct dio * dio = (struct dio *) bio->bi_private;

		//unsigned long i_ino  = dio->inode->i_ino;
		unsigned long i_ino  = bio->bi_io_vec->bv_page->mapping->host->i_ino;

		int pid = bpf_get_current_pid_tgid();

		char 	comm2[50];
		char comm1[50] = "FILTER_CMD";

		bpf_get_current_comm(&comm2, sizeof(comm2));


		for (int i = 0; i < sizeof(comm1); ++i)
    		if (comm1[i] != comm2[i])
    			return 0;

		//if(FILTER_PID)
			//return 0;
		
		if(FILTER_FILE)
			return 0;

		unsigned long i_inop = dio->iocb->ki_filp->f_path.dentry->d_parent->d_inode->i_ino;

		//if(FILTER_DIR)
			//return 0;


		struct data_log log = {};

		log.timestamp = bpf_ktime_get_ns();
		log.address = bio->bi_iter.bi_sector; 
		log.size = ((bio->bi_iter).bi_size >> 9) * SECTOR_SIZE;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'B';
		log.op  = (((bio->bi_opf & REQ_OP_MASK)) & 1) ? IO_WRITE_EVENT : IO_READ_EVENT;

		log.probe = '6';
		log.inode = i_ino;
		log.inodep = i_inop;
		


		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}


	int bio_endio_handler(struct pt_regs *ctx, struct bio *bio){
		bpf_trace_printk("bio_endio\\n");

		struct dio * dio = (struct dio *) bio->bi_private;

		//unsigned long i_ino  = dio->inode->i_ino;
		unsigned long i_ino  = bio->bi_io_vec->bv_page->mapping->host->i_ino;

		int pid = bpf_get_current_pid_tgid();

		char 	comm2[50];
		char comm1[50] = "FILTER_CMD";

		bpf_get_current_comm(&comm2, sizeof(comm2));


		for (int i = 0; i < sizeof(comm1); ++i)
    		if (comm1[i] != comm2[i])
    			return 0;

		//if(FILTER_PID)
			//return 0;
		
		if(FILTER_FILE)
			return 0;

		unsigned long i_inop = dio->iocb->ki_filp->f_path.dentry->d_parent->d_inode->i_ino;

		//if(FILTER_DIR)
			//return 0;

		struct data_log log = {};

		log.timestamp = bpf_ktime_get_ns();
		log.address = bio->bi_iter.bi_sector; 
		log.size = ((bio->bi_iter).bi_size >> 9) * SECTOR_SIZE;
		log.pid = bpf_get_current_pid_tgid();
		log.level = 'B';
		log.op  = (((bio->bi_opf & REQ_OP_MASK)) & 1) ? IO_WRITE_EVENT : IO_READ_EVENT;

		log.probe = '8';
		log.inode = i_ino;
		log.inodep = i_inop;
		
		bpf_get_current_comm(&log.comm, sizeof(log.comm));

		events.perf_submit(ctx, &log, sizeof(log));

		return 0;
	}

""")


# code replacements

if args.task:
    #program = program.replace('FILTER_PID', 'pid != %s' % pid)
    program = program.replace('FILTER_CMD', '%s' % name)
    #print("FILTER_CMD")

else:
    print("you must specify the traced cmd")
    sys.exit()

if args.inode:
	#print("FILTER_INODE")
	if args.file:
		program = program.replace('FILTER_FILE', 'i_ino != %s' % args.inode)
		program = program.replace('FILTER_DIR', '0')
		#print("FILTER_FILE")

	elif args.dir:
		program = program.replace('FILTER_FILE', '0')
		program = program.replace('FILTER_DIR', 'i_inop != %s' % args.inode)
		#print("FILTER_DIR",args.inode)

	else:
		print("you must specify the filter: -f for file or -d for directory")
		sys.exit()

else:
    print("you must specify the traced dir/file inode")
    sys.exit()




b = BPF(text = program)

# Attach kprobes to the functions
######### VFS probes ############ 
b.attach_kprobe(event="vfs_write", fn_name="VFS_write_handler")
b.attach_kprobe(event="vfs_read", fn_name="VFS_read_handler")

######### Page cache probes ############ 
b.attach_kprobe(event="__generic_file_write_iter", fn_name="generic_file_write_iter_handler")
b.attach_kprobe(event="generic_file_read_iter", fn_name="generic_file_read_iter_handler")

######### FS probes ############ 
b.attach_kprobe(event="ext4_file_write_iter", fn_name="ext4_file_write_iter_handler")
b.attach_kprobe(event="ext4_file_read_iter", fn_name="ext4_file_read_iter_handler")

######### BLK probes ############ 
b.attach_kprobe(event="submit_bio", fn_name="submit_bio_handler")
b.attach_kprobe(event="bio_endio", fn_name="bio_endio_handler")

#class Data(ct.Structure):
    #_fields_ = [("timestamp", ct.c_ulonglong),("address", ct.c_ulonglong), ("size", ct.c_ulonglong), ("pid", ct.c_int), \
    #("level", ct.c_char), ("op", ct.c_char), ("comm", ct.c_char_p)]


# ------------------ Report traces to user -----------------------
# -------------------------------------------------------------------------
#print("Pour stopper eBPF ..... Ctrl+C")

# afficher_evenement parses messages received from perf_buffer_poll
def afficher_evenement(cpu, data, size):
    #evenement = ct.cast(data, ct.POINTER(Data)).contents
    evenement = b["events"].event(data)	
    log = (evenement.timestamp,evenement.level.decode("utf-8"),evenement.op.decode("utf-8"),evenement.address,evenement.size,evenement.probe.decode("utf-8"),evenement.pid,evenement.comm.decode("utf-8"), evenement.inode, evenement.inodep)
    format_ = "%.0f\t%s\t%s\t%.0f\t%.0f\t%s\t%d\t%s\t%.0f\t%.0f"
    print(format_ % log)
    #evenement = b["events"].event(data)
    #print("%.0f, %.0f, %.0f, %s, %s, %d, %s" ,evenement.timestamp,evenement.address,evenement.size,evenement.level,evenement.op,evenement.pid,evenement.comm)




b["events"].open_perf_buffer(afficher_evenement)

# print result to user
while 1:
    # read messages from PERF BUFFER and send them to afficher_evenement
    b.perf_buffer_poll()
