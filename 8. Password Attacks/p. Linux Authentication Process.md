 Linux-based distributions support various authentication mechanisms. One of the most commonly used is [Pluggable Authentication Modules (PAM)](https://web.archive.org/web/20220622215926/http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html). The modules responsible for this functionality, such as `pam_unix.so` or `pam_unix2.so`, are typically located in `/usr/lib/x86_64-linux-gnu/security/` on Debian-based systems.
 The `pam_unix.so` module uses standardized API calls from system libraries to update account information. The primary files it reads from and writes to are `/etc/passwd` and `/etc/shadow`. PAM also includes many other service modules, such as those for LDAP, mount operations, and Kerberos authentication.
## Passwd file
The `/etc/passwd` file contains information about every user on the system and is readable by all users and services.

```shell-session
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

| Field                                              | Value               |
| -------------------------------------------------- | ------------------- |
| Username                                           | `htb-student`       |
| Password                                           | `x`                 |
| User ID                                            | `1000`              |
| Group ID                                           | `1000`              |
| [GECOS](https://en.wikipedia.org/wiki/Gecos_field) | `,,,`               |
| Home directory                                     | `/home/htb-student` |
| Default shell                                      | `/bin/bash`         |
The most relevant field for our purposes is the `Password` field, as it can contain different types of entries. In rare cases (generally on very old systems) this field may hold the actual password hash. On modern systems, however, password hashes are stored in the `/etc/shadow` file, which we'll examine later. Despite this, the `/etc/passwd` file is world-readable, giving attackers the ability to crack the passwords if hashes are stored here.

Usually, we will find the value `x` in this field, indicating that the passwords are stored in a hashed form within the `/etc/shadow` file. However, it can also be that the `/etc/passwd` file is writeable by mistake. This would allow us to remove the password field for the `root` user entirely.

```shell-session
head -n 1 /etc/passwd

root::0:0:root:/root:/bin/bash
```
This results in no password prompt being displayed when attempting to log in as `root`.

## Shadow file
It has a similar format to `/etc/passwd` but is solely responsible for password storage and management. It contains all password information for created users. For example, if there is no entry in the `/etc/shadow` file for a user listed in `/etc/passwd`, that user is considered invalid. The `/etc/shadow` file is also only readable by users with administrative privileges. The format of this file is divided into the following `nine fields`:

```shell-session
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```

|Field|Value|
|---|---|
|Username|`htb-student`|
|Password|`$y$j9T$3QSBB6CbHEu...SNIP...f8Ms`|
|Last change|`18955`|
|Min age|`0`|
|Max age|`99999`|
|Warning period|`7`|
|Inactivity period|`-`|
|Expiration date|`-`|
|Reserved field|`-`|
If the `Password` field contains a character such as `!` or `*`, the user cannot log in using a Unix password. However, other authentication methods—such as Kerberos or key-based authentication—can still be used.
The same applies if the `Password` field is empty, meaning no password is required for login. This can lead to certain programs denying access to specific functions. The `Password` field also follows a particular format, from which we can extract additional information:

- `$<id>$<salt>$<hashed>`

As we can see here, the hashed passwords are divided into three parts. The `ID` value specifies which cryptographic hash algorithm was used, typically one of the following:

| ID     | Cryptographic Hash Algorithm                                          |
| ------ | --------------------------------------------------------------------- |
| `1`    | [MD5](https://en.wikipedia.org/wiki/MD5)                              |
| `2a`   | [Blowfish](https://en.wikipedia.org/wiki/Blowfish_\(cipher\))         |
| `5`    | [SHA-256](https://en.wikipedia.org/wiki/SHA-2)                        |
| `6`    | [SHA-512](https://en.wikipedia.org/wiki/SHA-2)                        |
| `sha1` | [SHA1crypt](https://en.wikipedia.org/wiki/SHA-1)                      |
| `y`    | [Yescrypt](https://github.com/openwall/yescrypt)                      |
| `gy`   | [Gost-yescrypt](https://www.openwall.com/lists/yescrypt/2019/06/30/1) |
| `7`    | [Scrypt](https://en.wikipedia.org/wiki/Scrypt)                        |
## Opasswd

The PAM library (`pam_unix.so`) can prevent users from reusing old passwords. These previous passwords are stored in the `/etc/security/opasswd` file. Administrator (root) privileges are required to read this file, assuming its permissions have not been modified manually.
```shell
> sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```
Looking at the contents of this file, we can see that it contains several entries for the user `cry0l1t3`, separated by a comma (`,`). One critical detail to pay attention to is the type of hash that's been used. This is because the `MD5` (`$1$`) algorithm is significantly easier to crack than SHA-512.

## Cracking Linux Credentials

```shell-session
sudo cp /etc/passwd /tmp/passwd.bak
```

```shell-session
sudo cp /etc/shadow /tmp/shadow.bak 
```

```shell-session
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

This "unshadowed" file can now be attacked with either JtR or hashcat.

```shell
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

**Note:** This is the exact scenario that JtR's `single crack mode` was designed for.


### Questions 

1. Download the attached ZIP file (linux-authentication-process.zip), and use single crack mode to find martin's password. What is it?

```shell
> unshadow passwd shadow > unshadowed

> john --single unshadowed
Martin1          (martin)   
```

2. Use a wordlist attack to find sarah's password. What is it? 

```shell
> hashcat -a 0 -m 1800 hash /usr/share/wordlists/rockyou.txt
$6$EBOM5vJAV1TPvrdP$LqsLyYkoGzAGt4ihyvfhvBrrGpVjV976B3dEubi9i95P5cDx1U6BrE9G020PWuaeI6JSNaIDIbn43uskRDG0U/:mariposa 

```