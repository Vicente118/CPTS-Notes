### FTP
The File Transfer Protocol (FTP) is one of the oldest protocols on the Internet. The FTP runs within the application layer of the TCP/IP protocol stack


#### TFTP
Trivial File Transfer Protocol (TFTP) is simpler than FTP and performs file transfers between client and server processes. (UDP)
Unlike the FTP client, TFTP does not have directory listing functionality.


#### Default Configuration
One of the most used FTP servers on Linux-based distributions is vsFTPd. The default configuration of vsFTPd can be found in `/etc/vsftpd.conf`

```
Setting 	                                        Description
listen=NO 	                                        Run from inetd or as a standalone daemon?
listen_ipv6=YES 	                                Listen on IPv6 ?
anonymous_enable=NO 	                            Enable Anonymous access?
local_enable=YES 	                                Allow local users to login?
dirmessage_enable=YES 	                            Display active directory messages when users go into certain directories?
use_localtime=YES 	                                Use local time?
xferlog_enable=YES 	                                Activate logging of uploads/downloads?
connect_from_port_20=YES 	                        Connect from port 20?
secure_chroot_dir=/var/run/vsftpd/empty 	        Name of an empty directory
pam_service_name=vsftpd 	                        This string is the name of the PAM service vsftpd will use.
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem 	The last three options specify the location of the RSA certificate to use for SSL encrypted connections.
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key 	
ssl_enable=NO
```

In addition, there is a file called `/etc/ftpusers` that we also need to pay attention to, as this file is used to deny certain users access to the FTP service.

#### Dangerous Settings
```
Setting                                             Description
anonymous_enable=YES 	                            Allowing anonymous login?
anon_upload_enable=YES 	                            Allowing anonymous to upload files?
anon_mkdir_write_enable=YES 	                    Allowing anonymous to create new directories?
no_anon_password=YES 	                            Do not ask anonymous for password?
anon_root=/home/username/ftp 	                    Directory for anonymous.
write_enable=YES 	                                Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE?
```

#### vsFTPd Detailed Output
- status
- debug
- trace


#### Download All Available Files

```bash
$ wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

#### Upload a File

```bash
$ put file_to_upload.txt
$ put reverse_shell.php (In order to execute it via curl or browser if the webserver support php execution)
```

#### Footprinting the Service

```bash
Update nmap scripts database:
$ sudo nmap --script-updatedb

Find scripts:
$ find / -type f -name ftp* 2>/dev/null | grep scripts
/usr/share/nmap/scripts/ftp-syst.nse
/usr/share/nmap/scripts/ftp-vsftpd-backdoor.nse
/usr/share/nmap/scripts/ftp-vuln-cve2010-4221.nse
/usr/share/nmap/scripts/ftp-proftpd-backdoor.nse
/usr/share/nmap/scripts/ftp-bounce.nse
/usr/share/nmap/scripts/ftp-libopie.nse
/usr/share/nmap/scripts/ftp-anon.nse
/usr/share/nmap/scripts/ftp-brute.nse
```

#### Service Interation

```bash
$ nc -nv 10.129.14.136 21

If TLS/SSL is activated (Can give informations about the certificate):
$ openssl s_client -connect 10.129.14.136:21 -starttls ftp
```