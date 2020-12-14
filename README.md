# bpftrace_iotracer_like

## dependencies: bpftrace, fio

Installation:

`sudo apt-get update -y`

`sudo apt-get install -y fio`

`sudo snap install --devmode bpftrace `


## execution

`sudo bpftrace iotracer.bt [inode_of_file_to_be_traced] > trace_output`

do Ctrl+c to stop tracing (after launching the fio test script)

do `./script traced_file_path`  




