#!/bin/bash


hdd="/media/islam/1698B82098B7FFF3/"
ssd=""

device=$hdd

fin=$device"files/iotracer_test_file"
#fin="iotracer_test_file"
#fin="device"files/iotracer_test_file"
fout2="iotracer_test_file2"
fout3=$device"files/iotracer_test_file3"
fout4=$device"files/iotracer_test_file4"
fout5=$device"files/iotracer_test_file5"
fout6=$device"files/iotracer_test_file6"


traced=$device"files/"
inode=`stat -c '%i' $traced`

echo $inode

echo "cleanning files/"

# creation of the input file
#dd if=/dev/zero  of=$fin bs=8k count=100000 oflag=direct conv=fdatasync

mkdir -p /tmp/result

echo "trace: vfpb"

for (( i = 0; i < 10; i++ )); do

	rm -rf files/*

	sudo sync; echo 3 > /proc/sys/vm/drop_caches
	echo "" > $fout2

	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread  --direct=1  \
	--size=1G --bs=8k --numjobs=1  >> result/fio.txt

	#dd if=$fin  of=$fout2 bs=8k count=100000 iflag=direct  oflag=direct conv=fdatasync 2>> result/dd.txt 


	sudo sync; echo 3 > /proc/sys/vm/drop_caches
	echo "" > $fout3

			
	sudo python bcc_iotracer.py -t fio --dir -i $inode -l vfpb > /tmp/result/fio_ebpf_vfpb &
	echo "running bcc"



	#echo "running dd ..." 
	#dd if=$fin  of=$fout3 bs=8k count=100000  2>> result/dd-ebpf.txt
	#dd if=$fin  of=$fout5 bs=8k count=100000 iflag=direct  conv=fdatasync oflag=direct 2>> result/dd-ebpf.txt &
	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync &
	#dd if=$fin of=$fout bs=8k count=50000 oflag=direct &
	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync oflag=direct & # trace que vfs_write

	echo "running fio ..." 
	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread  --direct=1  \
	--size=1G --bs=8k --numjobs=1  >> result/fio-ebpf.txt


	echo "dd process is finished ..." 

	sudo kill $(pidof python)
	echo "stopping bcc ..." 

	wc -l /tmp/result/fio_ebpf_vfpb >> result/nb_event

done # outer for


echo "=================================== " >> result/fio.txt 
echo "=================================== " >> result/fio-ebpf.txt 

echo "trace: v"

for (( i = 0; i < 10; i++ )); do

	rm -rf files/*

	sudo sync; echo 3 > /proc/sys/vm/drop_caches
	echo "" > $fout2

	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread  --direct=1  \
	--size=1G --bs=8k --numjobs=1  >> result/fio.txt

	#dd if=$fin  of=$fout2 bs=8k count=100000 iflag=direct  oflag=direct conv=fdatasync 2>> result/dd.txt 


	sudo sync; echo 3 > /proc/sys/vm/drop_caches
	echo "" > $fout3

			
	sudo python bcc_iotracer.py -t fio --dir -i $inode -l v > /tmp/result/fio_ebpf_v &
	echo "running bcc"



	#echo "running dd ..." 
	#dd if=$fin  of=$fout3 bs=8k count=100000  2>> result/dd-ebpf.txt
	#dd if=$fin  of=$fout5 bs=8k count=100000 iflag=direct  conv=fdatasync oflag=direct 2>> result/dd-ebpf.txt &
	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync &
	#dd if=$fin of=$fout bs=8k count=50000 oflag=direct &
	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync oflag=direct & # trace que vfs_write

	echo "running fio ..." 
	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread  --direct=1  \
	--size=1G --bs=8k --numjobs=1  >> result/fio-ebpf.txt


	echo "dd process is finished ..." 

	sudo kill $(pidof python)
	echo "stopping bcc ..." 

	wc -l /tmp/result/fio_ebpf_v >> result/nb_event

done # outer for


echo "=================================== " >> result/fio.txt 
echo "=================================== " >> result/fio-ebpf.txt 


echo "trace: f"
for (( i = 0; i < 10; i++ )); do

	rm -rf files/*

	sudo sync; echo 3 > /proc/sys/vm/drop_caches
	echo "" > $fout2

	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread  --direct=1  \
	--size=1G --bs=8k --numjobs=1  >> result/fio.txt

	#dd if=$fin  of=$fout2 bs=8k count=100000 iflag=direct  oflag=direct conv=fdatasync 2>> result/dd.txt 


	sudo sync; echo 3 > /proc/sys/vm/drop_caches
	echo "" > $fout3

			
	sudo python bcc_iotracer.py -t fio --dir -i $inode -l f > /tmp/result/fio_ebpf_f &
	echo "running bcc"



	#echo "running dd ..." 
	#dd if=$fin  of=$fout3 bs=8k count=100000  2>> result/dd-ebpf.txt
	#dd if=$fin  of=$fout5 bs=8k count=100000 iflag=direct  conv=fdatasync oflag=direct 2>> result/dd-ebpf.txt &
	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync &
	#dd if=$fin of=$fout bs=8k count=50000 oflag=direct &
	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync oflag=direct & # trace que vfs_write

	echo "running fio ..." 
	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread  --direct=1  \
	--size=1G --bs=8k --numjobs=1  >> result/fio-ebpf.txt


	echo "dd process is finished ..." 

	sudo kill $(pidof python)
	echo "stopping bcc ..." 

	wc -l /tmp/result/fio_ebpf_f >> result/nb_event

done # outer for 

echo "=================================== " >> result/fio.txt 
echo "=================================== " >> result/fio-ebpf.txt

echo "trace: p"
for (( i = 0; i < 10; i++ )); do

	rm -rf files/*

	sudo sync; echo 3 > /proc/sys/vm/drop_caches
	echo "" > $fout2

	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread  --direct=1  \
	--size=1G --bs=8k --numjobs=1  >> result/fio.txt

	#dd if=$fin  of=$fout2 bs=8k count=100000 iflag=direct  oflag=direct conv=fdatasync 2>> result/dd.txt 


	sudo sync; echo 3 > /proc/sys/vm/drop_caches
	echo "" > $fout3

			
	sudo python bcc_iotracer.py -t fio --dir -i $inode -l p > /tmp/result/fio_ebpf_p &
	echo "running bcc"



	#echo "running dd ..." 
	#dd if=$fin  of=$fout3 bs=8k count=100000  2>> result/dd-ebpf.txt
	#dd if=$fin  of=$fout5 bs=8k count=100000 iflag=direct  conv=fdatasync oflag=direct 2>> result/dd-ebpf.txt &
	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync &
	#dd if=$fin of=$fout bs=8k count=50000 oflag=direct &
	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync oflag=direct & # trace que vfs_write

	echo "running fio ..." 
	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread  --direct=1  \
	--size=1G --bs=8k --numjobs=1  >> result/fio-ebpf.txt


	echo "dd process is finished ..." 

	sudo kill $(pidof python)
	echo "stopping bcc ..." 

	wc -l /tmp/result/fio_ebpf_p >> result/nb_event

done # outer for

echo "=================================== " >> result/fio.txt 
echo "=================================== " >> result/fio-ebpf.txt

# echo "trace: p2"
# for (( i = 0; i < 10; i++ )); do

# 	rm -rf files/*

# 	sudo sync; echo 3 > /proc/sys/vm/drop_caches
# 	echo "" > $fout2

# 	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread \
# 	--size=1G --bs=8k --numjobs=1  >> result/fio.txt

# 	#dd if=$fin  of=$fout2 bs=8k count=100000 iflag=direct  oflag=direct conv=fdatasync 2>> result/dd.txt 


# 	sudo sync; echo 3 > /proc/sys/vm/drop_caches
# 	echo "" > $fout3

			
# 	sudo python bcc_iotracer.py -t fio --dir -i $inode -l p > /tmp/result/fio_ebpf_p2 &
# 	echo "running bcc"



# 	#echo "running dd ..." 
# 	#dd if=$fin  of=$fout3 bs=8k count=100000  2>> result/dd-ebpf.txt
# 	#dd if=$fin  of=$fout5 bs=8k count=100000 iflag=direct  conv=fdatasync oflag=direct 2>> result/dd-ebpf.txt &
# 	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync &
# 	#dd if=$fin of=$fout bs=8k count=50000 oflag=direct &
# 	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync oflag=direct & # trace que vfs_write

# 	echo "running fio ..." 
# 	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread \
# 	--size=1G --bs=8k --numjobs=1  >> result/fio-ebpf.txt


# 	echo "dd process is finished ..." 

# 	sudo kill $(pidof python)
# 	echo "stopping bcc ..." 

# 	wc -l /tmp/result/fio_ebpf_p2 >> result/nb_event

# done # outer for 

# echo "=================================== " >> result/fio.txt 
# echo "=================================== " >> result/fio-ebpf.txt

echo "trace: b"

for (( i = 0; i < 10; i++ )); do

	rm -rf files/*

	sudo sync; echo 3 > /proc/sys/vm/drop_caches
	echo "" > $fout2

	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread  --direct=1  \
	--size=1G --bs=8k --numjobs=8  >> result/fio.txt

	#dd if=$fin  of=$fout2 bs=8k count=100000 iflag=direct  oflag=direct conv=fdatasync 2>> result/dd.txt 


	sudo sync; echo 3 > /proc/sys/vm/drop_caches
	echo "" > $fout3

			
	sudo python bcc_iotracer.py -t fio --dir -i $inode -l b > /tmp/result/fio_ebpf_b &
	echo "running bcc"



	#echo "running dd ..." 
	#dd if=$fin  of=$fout3 bs=8k count=100000  2>> result/dd-ebpf.txt
	#dd if=$fin  of=$fout5 bs=8k count=100000 iflag=direct  conv=fdatasync oflag=direct 2>> result/dd-ebpf.txt &
	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync &
	#dd if=$fin of=$fout bs=8k count=50000 oflag=direct &
	#dd if=$fin of=$fout bs=8k count=50000 conv=fdatasync oflag=direct & # trace que vfs_write

	echo "running fio ..." 
	fio --rw=write --ioengine=sync --name=mytest --directory=$traced --filename=fout2 --thread  --direct=1  \
	--size=1G --bs=8k --numjobs=1  >> result/fio-ebpf.txt


	echo "dd process is finished ..." 

	sudo kill $(pidof python)
	echo "stopping bcc ..." 

	wc -l /tmp/result/fio_ebpf_b >> result/nb_event

done # outer for 
