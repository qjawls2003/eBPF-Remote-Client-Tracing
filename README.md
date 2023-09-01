# eBPF-Remote-Client-Tracing
**Description**: An eBPF agent to trace all execve syscall back to a SSH Client IP and port.

##Usage
```
sudo ./sshtrace [-a] [-p] [-v] [-w] [-h]
```
```
       ./sshtrace           # trace all ssh-spawned execve syscall\
       ./sshtrace -a        # trace all execve syscalls\
       ./sshtrace -p        # printf all logs\
       ./sshtrace -v        # verbose events
       ./sshtrace -w        # verbose warnings
       ./sshtrace -h        # show help
```
##Installation

Linux Distrubtion with eBPF
```
git clone https://github.com/qjawls2003/eBPF-Remote-Client-Tracing
```

