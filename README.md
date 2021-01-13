# bpftrace_iotracer_like

## dependencies: bpftrace, fio

Installation:

`sudo apt-get update -y`

`sudo apt-get install -y fio`

`sudo snap install --devmode bpftrace `

for more information: https://github.com/iovisor/bpftrace/blob/master/INSTALL.md


## execution

`sudo bpftrace iotracer.bt [traced_command_name] [traced_file_inode] > trace_output`

 




