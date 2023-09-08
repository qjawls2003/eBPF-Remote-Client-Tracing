# eBPF-Remote-Client-Tracing

**Description**: An eBPF agent to trace all execve syscall back to a SSH Client IP, port, and user.

**Purpose**: This program will reduce the amount of manual tracing work when conducting forensics on suspicious user activities.

This program allows you to *pin* attribution to all SSH clients. Once a client connects to the host, this program will attribute the client's original IP, port, and user to all command line and execve events.
The original client information will stay consistent during multiple layers of localhost-to-localhost ssh, sudo su, and the spawning any new shell (/bin/bash, /bin/sh, etc.)

**Example:**

You can see that the user *guac* from *192.168.85.129:50642* executed *ls /home*, *cat /etc/passwd*, and *cat /etc/shadow*

![log_2](https://github.com/qjawls2003/eBPF-Remote-Client-Tracing/assets/35247051/cfa011cc-f205-49b1-b57d-da69c6e6f373)

Then, the user *guac* performes *sudo su* and executes *cat /etc/passwd*. You can see that the original *IP:port* and *username* are preserved in the logs.

![log_3](https://github.com/qjawls2003/eBPF-Remote-Client-Tracing/assets/35247051/85b29ad4-ef17-4d4d-ac2c-7cd39f249eef)



## Idea

The core framework of this program revolves around SSH's use of getpeername and getsockname system calls. These system calls contains information about the client and the server IP and port. Using this information, we mapped a user activity (execve syscall) to its original SSH information. 
In order to this, we considered these cases:
1. SSH from Remote location
2. SSH from localhost (multiple layers)
3. Privilege Escalation (sudo su, etc.)
4. New shell (/bin/bash, etc.)

sshtrace program will output the original IP, port, and user regardless of certain attempts at obfuscating its remote IP address. 
More detailed description of the program: [https://medium.com/etracing/tracing-ssh-user-activities-using-ebpf-c83f8f5a4a8e]

## Usage
```
sudo ./sshtrace [-a] [-p] [-v] [-w] [-h] [--max-args MAX_ARGS]
```
```
       ./sshtrace           # trace all ssh-spawned execve syscall\
       ./sshtrace -a        # trace all execve syscalls\
       ./sshtrace -p        # printf all logs\
       ./sshtrace -v        # verbose events
       ./sshtrace -w        # verbose warnings
       ./sshtrace -h        # show help
```
## Installation

Linux Distrubtion with eBPF
```
git clone https://github.com/qjawls2003/eBPF-Remote-Client-Tracing
cd /eBPF-Remote-Client-Tracing
sudo ./sshtrace
```

If you want to **Make** your own executable:
```
git clone --recurse-submodules https://github.com/qjawls2003/eBPF-Remote-Client-Tracing
sudo apt-get install bpftool
sudo apt-get install clang
sudo apt-get install libbpf-dev
sudo apt-get install gcc-multilib
sudo apt-get install llvm  
make
```

## Logging

The logs are generated in a JSON format (not JSON object).
```
/var/log/sshtrace.log
```
![log_1](https://github.com/qjawls2003/eBPF-Remote-Client-Tracing/assets/35247051/75991028-a4c2-4fee-8fbb-1f81296a9528)

## Monitoring

Use the *-p* arg to print out the logs:
```
sudo ./sshtrace -p
```
### IPv4
![ssh_1](https://github.com/qjawls2003/eBPF-Remote-Client-Tracing/assets/35247051/b326e22a-7ac5-4f98-9535-d18f6d5b02c2)

### IPv6
![ssh_3](https://github.com/qjawls2003/eBPF-Remote-Client-Tracing/assets/35247051/b7bb856a-b762-498f-b2a3-da6df836dc1b)
