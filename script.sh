#!/bin/bash

#FioEngines=(sync psync posixaio pvsync vsync pvsync2)
FioEngines=(sync)
#echo "FioEngines: ${FioEngines[*]}"

#RequestTypes=(read write randread randwrite rw randrw)
RequestTypes=(randrw)
#echo "RequestTypes: ${RequestTypes[*]}"

#fin="/dev/urandom"
fin="iotracer_test_file"
fout="files/iotracer_test_file"
fout2="files/iotracer_test_file2"
fout3="files/iotracer_test_file3"
fout4="files/iotracer_test_file4"
fout5="files/iotracer_test_file5"
fout6="files/iotracer_test_file6"

traced="files"

inode=`stat -c '%i' $traced`

echo $inode

echo "cleanning result"
rm -rf result/*


for i in "${FioEngines[@]}"; do
	for j in "${RequestTypes[@]}"; do 

		# trace dd with bcc
		
		##echo "testing ${i} - ${j} ..."

		#/usr/bin/time --format '%U,%S,%E,%P,%M,%K,%F,%R,%W,%c,%w' -o \
		#result/bcc_stats_$i_$j.txt 

		#dd if=$fin  of=$fout  bs=8k count=100000  &
		#dd if=$fin  of=$fout2 bs=8k count=100000  &
		#dd if=$fin  of=$fout3 bs=8k count=100000  &
		#dd if=$fin  of=$fout4 bs=8k count=100000  &
		#dd if=$fin  of=$fout5 bs=8k count=100000  &
		dd if=$fin  of=$fout6 bs=8k count=100000 oflag=direct &
		#dd if=$fin of=$fout bs=8k count=100000 conv=fdatasync &
		#dd if=$fin of=$fout bs=8k count=100000 oflag=direct &
		#dd if=$fin of=$fout bs=8k count=100000 conv=fdatasync oflag=direct & # trace que vfs_write
		
		echo "running dd ..." 

		sudo python bcc_iotracer.py -t dd --dir -i $inode > result/bcc_$i_$j &

		echo "running bcc"

		
		# test if fio is terminated 
		while kill -0 $(pidof dd) 2> /dev/null; do 
			sleep 1; 
		done;  # wait for the process to finish

		sleep 3;

		echo "dd process is finished ..." 

		sudo kill $(pidof python)
		echo "stopping bcc ..." 

		#cat result/bcc_stats_$i_$j.txt >> result/bcc_stats.txt
		#sudo wc -l result/bcc_$i_$j >> result/bcc_events.txt
		

	done # inner for
done # outer for 
