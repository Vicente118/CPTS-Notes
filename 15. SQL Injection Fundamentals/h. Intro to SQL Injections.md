## Use of SQL in Web Applications
For example, within a `PHP` web application, we can connect to our database, and start using the `MySQL` database through `MySQL` syntax, right within `PHP`, as follows:
```php
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);
```

hen, the query's output will be stored in `$result`, and we can print it to the page or use it in any other way. The below PHP code will print all returned results of the SQL query in new lines:
```php
while($row = $result->fetch_assoc() ){
	echo $row["name"]."<br>";
}
```

Web applications also usually use user-input when retrieving data. For example, when a user uses the search function to search for other users, their search input is passed to the web application, which uses the input to search within the databases:
```php
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

## What is an Injection?
In the above example, we accept user input and pass it directly to the SQL query without sanitization.
Injection occurs when an application misinterprets user input as actual code rather than a string, changing the code flow and executing it. This can occur by escaping user-input bounds by injecting a special character like (`'`), and then writing code to be executed, like JavaScript code or SQL in SQL Injections. Unless the user input is sanitized, it is very likely to execute the injected code and run it.

## SQL Injection
An SQL injection occurs when user-input is inputted into the SQL query string without properly sanitizing or filtering the input.
```php
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

In typical cases, the `searchInput` would be inputted to complete the query, returning the expected outcome. Any input we type goes into the following SQL query:
```sql
select * from logins where username like '%$searchInput'
```

However, as there is no sanitization, in this case, **we can add a single quote (`'`), which will end the user-input field, and after it, we can write actual SQL code**. For example, if we search for `1'; DROP TABLE users;`, the search input would be:
```php
'%1'; DROP TABLE users;' 
```
So, the final SQL query executed would be as follows:

```sql
select * from logins where username like '%1'; DROP TABLE users;'
```
*!* Though this is actually not possible with MySQL, it is possible with MSSQL and PostgreSQL. In the coming sections, we'll discuss the real methods of injecting SQL queries in MySQL.

## Syntax Errors
The previous example of SQL injection would return an error:
```php
Error: near line 1: near "'": syntax error
```

This is because of the last trailing character, where we have a single extra quote (`'`) that is not closed, which causes a SQL syntax error when executed:
```sql
select * from logins where username like '%1'; DROP TABLE users;'
```

To have a successful injection, we must ensure that the newly modified SQL query is still valid and does not have any syntax errors after our injection. In most cases, we would not have access to the source code to find the original SQL query and develop a proper SQL injection to make a valid SQL query. So, how would we be able to inject into the SQL query then successfully?

One answer is by using `comments`, and we will discuss this in a later section. Another is to make the query syntax work by passing in multiple single quotes, as we will discuss next (`'`).

---
## Types of SQL Injections
![[Pasted image 20251118133943.png]]

