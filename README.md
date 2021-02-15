# IOTracer

## dependencies: bpftrace

Installation:

`sudo apt-get update -y`

`sudo snap install --devmode bpftrace `

for more information: https://github.com/iovisor/bpftrace/blob/master/INSTALL.md

# On Debian:

`sudo apt install linux-headers-amd64 bpftrace`


## execution

`sudo bpftrace iotracer.bt [traced_command_name] [traced_file_inode] > trace_output`

 




