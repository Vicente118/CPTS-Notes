## Comments
We can use two types of line comments with MySQL `--` and `#`, in addition to an in-line comment `/**/` (though this is not usually used in SQL injections). The `--` can be used as follows:
```SQL
SELECT username FROM logins; -- Selects usernames from the logins table 

+---------------+
| username      |
+---------------+
| admin         |
| administrator |
| john          |
| tom           |
+---------------+
```

Note: In SQL, using two dashes only is not enough to start a comment. So, there has to be an empty space after them, so the comment starts with (-- ), with a space at the end. This is sometimes URL encoded as (--+), as spaces in URLs are encoded as (+). To make it clear, we will add another (-) at the end (-- -), to show the use of a space character.

The `#` symbol can be used as well.
```SQL
mysql> SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
+----+----------+----------+---------------------+
```
Tip: if you are inputting your payload in the URL within a browser, a (#) symbol is usually considered as a tag, and will not be passed as part of the URL. In order to use (#) as a comment within a browser, we can use '%23', which is an URL encoded (#) symbol.

## Auth Bypass with comments
```sql
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
```
Let us try using these on the login page, and log in with the username `admin'--` and anything as the password:

![Admin panel showing an SQL query execution: SELECT * FROM logins WHERE username='admin'-- ' AND password='a'; with a message: Login successful as user: admin](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/33/admin_dash.png)

---
## Another Example
SQL supports the usage of parenthesis if the application needs to check for particular conditions before others. Expressions within the parenthesis take precedence over other operators and are evaluated first. Let us look at a scenario like this:

![Admin panel showing an SQL query execution: SELECT * FROM logins WHERE (username='admin' AND id > 1) AND password='437b930db84b8079c2dd804a71936b5f'; with a message: Login failed!](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/33/paranthesis_fail.png)
As expected, the login failed even though we supplied valid credentials because the admin’s ID equals 1. So let us try logging in with the credentials of another user, such as `tom`.

![Admin panel showing an SQL query execution: SELECT * FROM logins WHERE (username='tom' AND id > 1) AND password='f86a3c565937e6315864d1a43c48e7'; with a message: Login successful as user: tom"](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/33/tom_login.png)

Logging in as the user with an id not equal to 1 was successful. So, how can we log in as the admin? We know from the previous section on comments that we can use them to comment out the rest of the query. So, let us try using `admin'--` as the username.

![Admin panel showing an SQL query execution: SELECT * FROM logins WHERE (username='admin'--' AND id > 1) AND password='437b930db84b8079c2dd804a71936b5f'; with an error message: You have an error in your SQL syntax; check the manual for the right syntax near '437b930db84b8079c2dd804a71936b5f' at line 1](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/33/paranthesis_error.png)

The login failed due to a syntax error, as a closed one did not balance the open parenthesis. To execute the query successfully, we will have to add a closing parenthesis. Let us try using the username `admin')--` to close and comment out the rest.

![Admin panel showing an SQL query execution: SELECT * FROM logins WHERE (username='admin'--' AND id > 1) AND password='437b930db84b8079c2dd804a71936b5f'; with a message: Login successful as user: admin"](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/33/paranthesis_success.png)

The query was successful, and we logged in as admin. The final query as a result of our input is:
```sql
SELECT * FROM logins where (username='admin')
```

