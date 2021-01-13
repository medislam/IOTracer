# bpftrace_iotracer_like

## dependencies: bpftrace

Installation:

`sudo apt-get update -y`

`sudo snap install --devmode bpftrace `

for more information: https://github.com/iovisor/bpftrace/blob/master/INSTALL.md


## execution

`sudo bpftrace iotracer.bt [traced_command_name] [traced_file_inode] > trace_output`

 




