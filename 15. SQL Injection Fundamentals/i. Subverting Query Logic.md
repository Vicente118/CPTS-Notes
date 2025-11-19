## Authentication Bypass
![[Pasted image 20251118135531.png]]We can log in with the administrator credentials `admin / p@ssw0rd`.
Our goal is to log in as the admin user without using the existing password. As we can see, the current SQL query being executed is:
```sql
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
```

The page takes in the credentials, then uses the `AND` operator to select records matching the given username and password. If the `MySQL` database returns matched records, the credentials are valid, so the `PHP` code would evaluate the login attempt condition as `true`. If the condition evaluates to `true`, the admin record is returned, and our login is validated. Let us see what happens when we enter incorrect credentials.
![[Pasted image 20251118141044.png]]

---
## SQLi Discovery
To do that, we will try to add one of the below payloads after our username and see if it causes any errors or changes how the page behaves:

|Payload|URL Encoded|
|---|---|
|`'`|`%27`|
|`"`|`%22`|
|`#`|`%23`|
|`;`|`%3B`|
|`)`|`%29`|

Note: In some cases, we may have to use the URL encoded version of the payload. An example of this is when we put our payload directly in the URL 'i.e. HTTP GET request'.

So, let us start by injecting a single quote:
![[Pasted image 20251118141133.png]]
We see that a SQL error was thrown instead of the `Login Failed` message. The page threw an error because the resulting query was:
```sql
SELECT * FROM logins WHERE username=''' AND password = 'something';
```

---
## OR Injection
We would need the query always to return `true`, regardless of the username and password entered, to bypass the authentication. To do this, we can abuse the `OR` operator in our SQL injection.
```sql
admin' or '1'='1
```

The final query should be as follow:
```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```
**!!** `AND` operator would be evaluated before the `OR` operator.

This means the following:
- If username is `admin`  
    `OR`
- If `1=1` return `true` 'which always returns `true`'  
    `AND`
- If password is `something`
![[Pasted image 20251118142040.png]]
The `AND` operator is evaluated first:
- `'1'='1'` is `True`.
- `password='something'` is `False`.
- The result of the `AND` condition is `False` because `True AND False` is `False`.

Next, the `OR` operator is evaluated:
- If `username='admin'` exists, the entire query returns `True`.
- The `'1'='1'` condition is irrelevant in this context because it doesn't affect the outcome of the `AND` condition.

Therefore, the query will return `True` if a username `'admin'` exists, bypassing authentication.

Note: You can find a comprehensive list of SQLi auth bypass payloads in [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass), each of which works on a certain type of SQL queries.

## Auth Bypass with OR operator
Let us try this as the username and see the response. ![Admin panel showing an SQL query execution: SELECT * FROM logins WHERE username='admin' OR '1'='1' AND password='something'; with a message: Login successful as user: admin](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/33/inject_success.png)

 Let us try the same request with a different username this time.

![Admin panel showing an SQL query execution: SELECT * FROM logins WHERE username='notAdmin' OR '1'='1' AND password='something'; with a message: Login failed!](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/33/notadmin_fail.png)

The login failed because `notAdmin` does not exist in the table and resulted in a false query overall.

To successfully log in once again, we will need an overall `true` query. This can be achieved by injecting an `OR` condition into the password field, so it will always return `true`. Let us try `something' or '1'='1` as the password.
![[Pasted image 20251118142554.png]]

