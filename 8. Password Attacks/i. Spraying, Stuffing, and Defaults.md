## Password spraying
[Password spraying](https://owasp.org/www-community/attacks/Password_Spraying_Attack) is a type of brute-force attack in which an attacker attempts to use a single password across many different user accounts. This technique can be particularly effective in environments where users are initialized with a default or standard password. For example, if it is known that administrators at a particular company commonly use `ChangeMe123!` when setting up new accounts, it would be worthwhile to spray this password across all user accounts to identify any that were not updated.
Depending on the target system, different tools may be used to carry out password spraying attacks. For web applications, [Burp Suite](https://portswigger.net/burp) is a strong option, while for Active Directory environments, tools such as [NetExec](https://github.com/Pennyw0rth/NetExec) or [Kerbrute](https://github.com/ropnop/kerbrute) are commonly used.

```shell
netexec smb 10.100.38.0/24 -u <usernames.list> -p 'ChangeMe123!'
```

## Credential stuffing
[Credential stuffing](https://owasp.org/www-community/attacks/Credential_stuffing) is another type of brute-force attack in which an attacker uses stolen credentials from one service to attempt access on others. Since many users reuse their usernames and passwords across multiple platforms (such as email, social media, and enterprise systems), these attacks are sometimes successful.
For example, if we have a list of `username:password` credentials obtained from a database leak, we can use `hydra` to perform a credential stuffing attack against an SSH service using the following syntax:
```shell
hydra -C user_pass.list ssh://10.100.38.23
```

## Default credentials
Many systems—such as routers, firewalls, and databases—come with `default credentials`. While best practice dictates that administrators change these credentials during setup, they are sometimes left unchanged, posing a serious security risk.

```shell
creds search <service>
```
In addition to publicly available lists and tools, default credentials can often be found in product documentation, which typically outlines the steps required to set up a service.


### Questions

1.  Use the credentials provided to log into the target machine and retrieve the MySQL credentials. Submit them as the answer. (Format: username:password)

```shell
First use the creds command to see every MySQL default creds:
> mysql -u superdba -p'admin'

mysql > showdatabases;
```