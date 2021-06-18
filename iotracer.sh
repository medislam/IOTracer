#!/bin/bash

traced_inode=$(ls -d . -i |cut -f1 -d" ")
level="vpfb"
output_filename=iotracer_trace.txt

usage()
{
cat << EOF
usage: $0 [options] command

OPTIONS:
   -?                               Show this message
   -i <inode> 			    Select the inode to trace
   -d <dirname> 		    Select the directory to trace
   -o <filename>	       	    Select the output filename
   -l <level>	       	            Select events to trace
EOF
}


while getopts 'i:l:o:d:' OPTION; do
  case $OPTION in
      d)
	  traced_dir=$OPTARG
	  traced_inode=$(ls -d "$traced_dir" -i |cut -f1 -d" ")
	  ;;
      i)
	  traced_inode=$OPTARG
       	  ;;
      l)
	  level=$OPTARG
	  ;;
      o)
	  output_filename=$OPTARG
	  ;;
      
      ?)	usage
      exit 2
      ;;
  esac
done

# remove the options from the command line
shift $(($OPTIND - 1))

if [ $# -lt 2 ]; then
    usage
    exit 2
fi
cmd=$@
traced_task=$(basename $1)
trace_filter_option="-d"
IOTRACER=/home/ftrahay/Soft/eziotrace/src/iotracer/bcc_iotracer.py

echo "# Running python $IOTRACER -t $traced_task $trace_filter_option -i $traced_inode -l $level > iotracer_trace.txt &"
python $IOTRACER -t $traced_task $trace_filter_option -i $traced_inode -l $level > "$output_filename" &

iotracer_pid=$!


sleep 5
echo "# Running command $cmd"
$cmd


echo "# Killing IOTracer daemon $iotracer_pid"
kill -9 $iotracer_pid
nlines=$(wc -l "$output_filename")
echo "# Nb events: $nlines"
