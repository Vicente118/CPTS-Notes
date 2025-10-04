Nearly all corporate environments include network shares used by employees to store and share files across teams. While these shared folders are essential, they can unintentionally become a goldmine for attackers, especially when sensitive data like plaintext credentials or configuration files are left behind.

In this section, we'll explore how to hunt for credentials across network shares from both Windows and Linux systems using common tools, along with general techniques attackers use to uncover hidden secrets.

#### Common credential patterns
- Look for keywords within files such as `passw`, `user`, `token`, `key`, and `secret`.
- Search for files with extensions commonly associated with stored credentials, such as `.ini`, `.cfg`, `.env`, `.xlsx`, `.ps1`, and `.bat`.
- Watch for files with "interesting" names that include terms like `config`, `user`, `passw`, `cred`, or `initial`.
- If you're trying to locate credentials within the `INLANEFREIGHT.LOCAL` domain, it may be helpful to search for files containing the string `INLANEFREIGHT\`.
- Keywords should be localized based on the target; if you are attacking a German company, it's more likely they will reference a `"Benutzer"` than a `"User"`.
- Pay attention to the shares you are looking at, and be strategic. If you scan ten shares with thousands of files each, it's going to take a signifcant amount of time. Shares used by `IT employees` might be a more valuable target than those used for company photos.

With all of this in mind, you may want to begin with basic command-line searches (e.g., `Get-ChildItem -Recurse -Include *.ext \\Server\Share | Select-String -Pattern ...`) before scaling up to more advanced tools. Let's take a look at how we can use `MANSPIDER`, `Snaffler`, `SnafflePy`, and `NetExec` to automate and enhance this credential hunting process.

## Hunting from Windows
#### Snaffler
The first tool we will cover is [Snaffler](https://github.com/SnaffCon/Snaffler). This is a C# program that, when run on a `domain-joined` machine, automatically identifies accessible network shares and searches for interesting files. The `README` file in the Github repository describes the numerous configuration options in great detail, however a basic search can be carried out like so:

```cmd-session
c:\Users\Public>Snaffler.exe -s
```
Two useful parameters that can help refine Snaffler's search process are:
- `-u` retrieves a list of users from Active Directory and searches for references to them in files
- `-i` and `-n` allow you to specify which shares should be included in the search


#### PowerHuntShares
Another tool that can be used is [PowerHuntShares](https://github.com/NetSPI/PowerHuntShares), a PowerShell script that doesn't necessarily need to be run on a domain-joined machine. One of its most useful features is that it generates an `HTML report` upon completion, providing an easy-to-use UI for reviewing the results:
We can run a basic scan using `PowerHuntShares` like so:

```powershell
PS C:\Users\Public\PowerHuntShares> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public
```


## Hunting from Linux

#### MANSPIDER
If we don’t have access to a domain-joined computer, or simply prefer to search for files remotely, tools like [MANSPIDER](https://github.com/blacklanternsecurity/MANSPIDER) allow us to scan SMB shares from Linux. It's best to run `MANSPIDER` using the official Docker container to avoid dependency issues. Like the other tools, `MANSPIDER` offers many parameters that can be configured to fine-tune the search. A basic scan for files containing the string `passw` can be run as follows:

```shell
> docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.121 -c 'passw' -u 'mendres' -p 'Inlanefreight2025!'

[+] MANSPIDER command executed: /usr/local/bin/manspider 10.129.234.121 -c passw -u mendres -p Inlanefreight2025!
[+] Skipping files larger than 10.00MB
[+] Using 5 threads
[+] Searching by file content: "passw"
[+] Matching files will be downloaded to /root/.manspider/loot
[+] 10.129.234.121: Successful login as "mendres"
[+] 10.129.234.121: Successful login as "mendres"
```

#### NetExec
In addition to its many other uses, `NetExec` can also be used to search through network shares using the `--spider` option. This functionality is described in great detail on the [official wiki](https://www.netexec.wiki/smb-protocol/spidering-shares). A basic scan of network shares for files containing the string `"passw"` can be run like so:
```shell
> 

SMB         10.129.234.121  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:inlanefreight.local) (signing:True) (SMBv1:False)
SMB         10.129.234.121  445    DC01             [+] inlanefreight.local\mendres:Inlanefreight2025! 
SMB         10.129.234.121  445    DC01             [*] Started spidering
SMB         10.129.234.121  445    DC01             [*] Spidering .
<SNIP>
```

## Exercise
Use the credentials `mendres:Inlanefreight2025!` to connect to the target either by RDP or WinRM, then use the tools and techniques taught in this section to answer the questions below. For your convenience, `Snaffler` and `PowerHuntShares` can be found in `C:\Users\Public`.

## Questions

1. One of the shares mendres has access to contains valid credentials of another domain user. What is their password?
2. As this user, search through the additional shares they have access to and identify the password of a domain administrator. What is it?

---
1. We can spider the HR share with the string `passwd` :
```shell
> docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.173 -c 'pwd' -u 'mendres' -p 'Inlanefreight2025!'

(VERY BIG OUTPUT SO I GREPPED IT WITH passwd*)
...
...
...
[+] Auth backup password: INLANEFREIGHT\jbader:ILovePower333###
...
...
```
2. Make the same command with jbader user:
```shell
...
...
**Password:** `Str0ng_Adm1nistrat0r_P@ssword_2025!`
...
...
...
```