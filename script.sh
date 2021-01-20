#!/bin/bash

#FioEngines=(sync psync posixaio pvsync vsync pvsync2)
FioEngines=(sync)
#echo "FioEngines: ${FioEngines[*]}"

#RequestTypes=(read write randread randwrite rw randrw)
RequestTypes=(randrw)
#echo "RequestTypes: ${RequestTypes[*]}"

fin="/dev/urandom"
#fin="iotracer_test_file2"
fout="iotracer_test_file"

inode=`stat -c '%i' $fout`

echo $inode

echo "cleanning result"
rm -rf result/*


for i in "${FioEngines[@]}"; do
	for j in "${RequestTypes[@]}"; do 

		# trace dd with bcc
		
		##echo "testing ${i} - ${j} ..."

		#/usr/bin/time --format '%U,%S,%E,%P,%M,%K,%F,%R,%W,%c,%w' -o \
		#result/bcc_stats_$i_$j.txt 

		#dd if=$fin of=$fout bs=8k count=100000 &
		dd if=$fin of=$fout bs=8k count=100000 conv=fdatasync &
		#dd if=$fin of=$fout bs=8k count=100000 oflag=direct &
		#dd if=$fin of=$fout bs=8k count=100000 conv=fdatasync oflag=direct & # trace que vfs_write
		
		echo "running dd ..." 

		sudo python bcc_iotracer.py -t dd -i $inode > result/bcc_$i_$j &

		echo "running bcc"

		
		# test if fio is terminated 
		while kill -0 $(pidof dd) 2> /dev/null; do 
			sleep 1; 
		done;  # wait for the process to finish

		sleep 30;

		echo "dd process is finished ..." 

		kill $(pidof python)
		echo "stopping bcc ..." 

		#cat result/bcc_stats_$i_$j.txt >> result/bcc_stats.txt
		#sudo wc -l result/bcc_$i_$j >> result/bcc_events.txt
		

	done # inner for
done # outer for 
