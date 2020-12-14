#!/bin/bash

FioEngines=(sync psync posixaio pvsync vsync pvsync2)
#FioEngines=(sync posixaio)
echo "FioEngines: ${FioEngines[*]}"

RequestTypes=(read write randread randwrite rw randrw)
#RequestTypes=(randrw)
echo "RequestTypes: ${RequestTypes[*]}"

#create a file of 32MByte using dd
#dd if=/dev/zero of=/tmp/iotracer_test_file bs=1024K count=32 oflag=direct

for i in "${FioEngines[@]}"; do
	for j in "${RequestTypes[@]}"; do 
		
		echo "testing ${i} - ${j} ..."

		# execute the tracing code 
		#sudo bpftrace -e 'kprobe:vfs* /comm == "fio"/ { printf("@[%ld]\t%s\t%s\t%s\n", nsecs, comm, func, probe); }' > vfs_trace_bpftrace_${i}_${j} &
		echo "running bpftrace ..." 

		# launiching fio
		fio --name=test --filename=$1  --ioengine=$i --rw=$j -size=128M --bs=4k --direct=1 --numjobs=1 --group_reporting &

		echo "running fio ..." 

		# test if fio is terminated 
		while kill -0 $(pidof fio) 2> /dev/null; do 
			sleep 1; 
		done;  # wait for the process to finish

		sleep 3;

		//kill $(pidof bpftrace)
		echo "stopping bpftrace ..." 

	done # inner for
done # outer for 

