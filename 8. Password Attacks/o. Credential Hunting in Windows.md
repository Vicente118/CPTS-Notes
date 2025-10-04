`Credential hunting` is the process of performing detailed searches across the file system and through various applications to discover credentials. To understand this concept, let's place ourselves in a scenario. We have gained access to an IT admin's Windows 10 workstation through RDP.

## Search-centric
#### Key terms to search for
Here are some helpful key terms we can use that can help us discover some credentials:
- Passwords
- Passphrases
- Keys
- Username
- User account
- Creds
- Users
- Passkeys
- configuration
- dbcredential
- dbpassword
- pwd
- Login
- Credentials

## Search tools
#### Windows Search
![[Pasted image 20251003123322.png]]

#### LaZagne
We can also take advantage of third-party tools like [LaZagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store.
LaZagne is made up of `modules` which each target different software when looking for passwords. Some of the common modules are described in the table below:

|Module|Description|
|---|---|
|browsers|Extracts passwords from various browsers including Chromium, Firefox, Microsoft Edge, and Opera|
|chats|Extracts passwords from various chat applications including Skype|
|mails|Searches through mailboxes for passwords including Outlook and Thunderbird|
|memory|Dumps passwords from memory, targeting KeePass and LSASS|
|sysadmin|Extracts passwords from the configuration files of various sysadmin tools like OpenVPN and WinSCP|
|windows|Extracts Windows-specific credentials targeting LSA secrets, Credential Manager, and more|
|wifi|Dumps WiFi credentials|

**Note:** Web browsers are some of the most interesting places to search for credentials, due to the fact that many of them offer built-in credential storage. In the most popular browsers, such as `Google Chrome`, `Microsoft Edge`, and `Firefox`, stored credentials are encrypted. However, many tools for decrypting the various credentials databases used can be found online, such as [firefox_decrypt](https://github.com/unode/firefox_decrypt) and [decrypt-chrome-passwords](https://github.com/ohyicong/decrypt-chrome-passwords). LaZagne supports `35` different browsers on Windows.

```cmd-session
C:\Users\bob\Desktop> start LaZagne.exe all
```
This will execute LaZagne and run `all` included modules. We can include the option `-vv` to study what it is doing in the background. Once we hit enter, it will open another prompt and display the results.

Credential Hunting in Windows

```cmd-session
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22
```

#### findstr
We can also use [findstr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr) to search from patterns across many types of files. Keeping in mind common key terms, we can use variations of this command to discover credentials on a Windows target:

```cmd
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

## Additional considerations
Here are some other places we should keep in mind when credential hunting:
- Passwords in Group Policy in the SYSVOL share
- Passwords in scripts in the SYSVOL share
- Password in scripts on IT shares
- Passwords in `web.config` files on dev machines and IT shares
- Password in `unattend.xml`
- Passwords in the AD user or computer description fields
- KeePass databases (if we are able to guess or crack the master password)
- Found on user systems and shares
- Files with names like `pass.txt`, `passwords.docx`, `passwords.xlsx` found on user systems, shares, and [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)


### Questions

1. What password does Bob use to connect to the Switches via SSH? (Format: Case-Sensitive)
2.  What is the GitLab access code Bob uses? (Format: Case-Sensitive)
3. What credentials does Bob use with WinSCP to connect to the file server? (Format: username:password, Case-Sensitive)
4. What is the default password of every newly created Inlanefreight Domain user account? (Format: Case-Sensitive)
5. What are the credentials to access the Edge-Router? (Format: username:password, Case-Sensitive)

---

1. Open passwords.ods file in Excel and found this: `admin:WellConnected123` and `bwilliamson@P@55s0rd!`
2. Foud GitlabAccessCodeJustInCase.txt on Desktop folder: `3z1ePfGbjWPsTfCsZfjy`
3. Use Lazagne.exe and we found this: `ubuntu:FSadmin123` for WinSCP
4. We found the defautl password here: C:\Automation&Scripts\BulkaddADusers.ps1: `Inlanefreightisgreat2022`
5.  We found credentials in: C:\Automation&Scripts\AnsibleScripts\EdgeRoutersConfigs: `edgeadmin:Edge@dmin123!`