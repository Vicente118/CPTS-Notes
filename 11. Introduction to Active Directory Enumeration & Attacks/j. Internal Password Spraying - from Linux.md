## Internal Password Spraying from a Linux Host
`Rpcclient` is an excellent option for performing this attack from Linux. An important consideration is that a valid login is not immediately apparent with `rpcclient`, with the response `Authority Name` indicating a successful login. We can filter out invalid login attempts by `grepping` for `Authority` in the response. The following Bash one-liner (adapted from [here](https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/)) can be used to perform the attack.
#### Using a Bash one-liner for the Attack
```shell
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

We can also use `Kerbrute` for the same attack as discussed previously.

#### Using Kerbrute for the Attack
```shell
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

#### Using CrackMapExec & Filtering Logon Failures
```shell
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

**!** After getting one (or more!) hits with our password spraying attack, we can then use `CrackMapExec` to validate the credentials quickly against a Domain Controller.

#### Validating the Credentials with CrackMapExec
```shell
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

## Local Administrator Password Reuse
Internal password spraying is not only possible with domain user accounts. If you obtain administrative access and the NTLM password hash or cleartext password for the local administrator account (or another privileged local account), this can be attempted across multiple hosts in the network.

CrackMapExec is a handy tool for attempting this attack. It is worth targeting high-value hosts such as `SQL` or `Microsoft Exchange` servers, as they are more likely to have a highly privileged user logged in or have their credentials persistent in memory.

If we find a desktop host with the local administrator account password set to something unique such as `$desktop%@admin123`, it might be worth attempting `$server%@admin123` against servers.

Sometimes we may only retrieve the NTLM hash for the local administrator account from the local SAM database. In these instances, we can spray the NT hash across an entire subnet (or multiple subnets) to hunt for local administrator accounts with the same password set.

#### Local Admin Spraying with CrackMapExec
```shell
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```