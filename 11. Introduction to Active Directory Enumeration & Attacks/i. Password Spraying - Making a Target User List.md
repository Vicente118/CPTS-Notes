There are several ways that we can gather a target list of valid users:
- SMB NULL Session to retrieve a complete list of domain users from the domain controller.
- LDAP anonymous bind to query LDAP anonymously and pull down user list.
- using Kerbrute to validate users utilzing a word list such as [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) or gathered by using tool such as linkedin2username.
-  Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using `Responder` or even a successful password spray using a smaller wordlist

No matter the method we choose, it is also vital for us to consider the domain password policy. If we have an SMB NULL session, LDAP anonymous bind, or a set of valid credentials, we can enumerate the password policy.

## SMB NULL Session to Pull User List
If you are on an internal machine but don’t have valid domain credentials, you can look for SMB NULL sessions or LDAP anonymous binds on Domain Controllers. Either of these will allow you to obtain an accurate list of all users within Active Directory and the password policy. If you already have credentials for a domain user or `SYSTEM` access on a Windows host, then you can easily query Active Directory for this information.

It’s possible to do this using the SYSTEM account because it can `impersonate` the computer. A computer object is treated as a domain user account (with some differences, such as authenticating across forest trusts). If you don’t have a valid domain account, and SMB NULL sessions and LDAP anonymous binds are not possible, you can create a user list using external resources such as email harvesting and LinkedIn.

Some tools that can leverage SMB NULL sessions and LDAP anonymous binds include [enum4linux](https://github.com/portcullislabs/enum4linux), [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html), and [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), among others.

#### Using enum4linux
```shell
> enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

administrator
guest
krbtgt
lab_adm
htb-student
...
```


We can use the `enumdomusers` command after connecting anonymously using `rpcclient`.
#### Using rpcclient
```shell
rpcclient -U "" -N 172.16.5.5

rpcclient $> enumdomusers 
user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[lab_adm] rid:[0x3e9]
user:[htb-student] rid:[0x457]
user:[avazquez] rid:[0x458]

<SNIP>
```

Finally, we can use `CrackMapExec` with the `--users` flag. This is a useful tool that will also show the `badpwdcount` (invalid login attempts), so we can remove any accounts from our list that are close to the lockout threshold.
#### Using NetExec --users Flag
```shell
> nxc smb 172.16.5.5 --users

SMB   172.16.5.5  445  ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB   172.16.5.5  445  ACADEMY-EA-DC01  [+] Enumerated domain user(s)
SMB   172.16.5.5  445  ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\administrator                  badpwdcount: 0 baddpwdtime: 2022-01-10 13:23:09.463228
```

---
## Gathering Users with LDAP Anonymous
We can use various tools to gather users when we find an LDAP anonymous bind. Some examples include [windapsearch](https://github.com/ropnop/windapsearch) and [ldapsearch](https://linux.die.net/man/1/ldapsearch).

#### Using ldapsearch
```shell
> ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

guest
ACADEMY-EA-DC01$
ACADEMY-EA-MS01$
ACADEMY-EA-WEB01$
htb-student
avazquez
```
Tools such as `windapsearch` make this easier (though we should still understand how to create our own LDAP search filters). Here we can specify anonymous access by providing a blank username with the `-u` flag and the `-U` flag to tell the tool to retrieve just users.
#### Using windapsearch
```shell
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

----
## Enumerating Users with Kerbrute
This tool uses [Kerberos Pre-Authentication](https://ldapwiki.com/wiki/Wiki.jsp?page=Kerberos%20Pre-Authentication), which is a much faster and potentially stealthier way to perform password spraying. This method does not generate Windows event ID [4625: An account failed to log on](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625), or a logon failure which is often monitored for.
#### Kerbrute User Enumeration
```shell
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```
We've checked over 48,000 usernames in just over 12 seconds and discovered 50+ valid ones. Using Kerbrute for username enumeration will generate event ID [4768: A Kerberos authentication ticket (TGT) was requested](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768). This will only be triggered if [Kerberos event logging](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging) is enabled via Group Policy. Defenders can tune their SIEM tools to look for an influx of this event ID, which may indicate an attack.

---

## Credentialed Enumeration to Build our User List
With valid credentials, we can use any of the tools stated previously to build a user list. A quick and easy way is using NetExec.
#### Using NetExec with Valid Credentials
```shell
sudo nxc smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

