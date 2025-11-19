## Structured Query Language (SQL)\
SQL can be used to perform the following actions:
- Retrieve data
- Update data
- Delete data
- Create new tables and databases
- Add / remove users
- Assign permissions to these users

## Command Line
```shell
mysql -u root -p
```

```shell
mysql -u root -p<password>
```
Tip: There shouldn't be any spaces between '-p' and the password.

When we do not specify a host, it will default to the `localhost` server. We can specify a remote host and port using the `-h` and `-P` flags.

```shell
mysql -u root -h <ip> -P <port> -p 
```

## Creating a database
```shell
mysql> CREATE DATABASE users;
```

```shell-session
mysql> SHOW DATABASES;
```

```SQL
mysql> USE users;
```


## Tables
A table is made up of horizontal rows and vertical columns. The intersection of a row and a column is called a cell.

A data type defines what kind of value is to be held by a column. Common examples are `numbers`, `strings`, `date`, `time`, and `binary data`. There could be data types specific to DBMS as well. A complete list of data types in MySQL can be found [here](https://dev.mysql.com/doc/refman/8.0/en/data-types.html). For example, let us create a table named `logins` to store user data, using the [CREATE TABLE](https://dev.mysql.com/doc/refman/8.0/en/creating-tables.html) SQL query:

```SQL
CREATE TABLE logins (
	id INT,
	username VARCHAR(100),
	password VARCHAR(100),
	data_of_joining DATETIME
	);
```
As we can see, the `CREATE TABLE` query first specifies the table name, and then (within parentheses) we specify each column by its name and its data type

The SQL queries above create a table named `logins` with four columns.

```SQL
sql> show tables;
```
##### List table structure
```
sql> describe logins;
```

#### Table Properties
##### Not NULL + Auto Incrementation
Within the `CREATE TABLE` query, there are many [properties](https://dev.mysql.com/doc/refman/8.0/en/create-table.html) that can be set for the table and each column. For example, we can set the `id` column to auto-increment using the `AUTO_INCREMENT` keyword, which automatically increments the id by one every time a new item is added to the table:
```sql
id INT NOT NULL AUTO_INCREMENT,
```
The `NOT NULL` constraint ensures that a particular column is never left empty

##### Unique value
We can also use the `UNIQUE` constraint to ensures that the inserted item are always unique. For example, if we use it with the `username` column, we can ensure that no two users will have the same username:
```sql
username VARCHAR(100) UNIQUE NOT NULL,
```

##### Default value
Another important keyword is the `DEFAULT` keyword, which is used to specify the default value. For example, within the `date_of_joining` column, we can set the default value to [Now()](https://dev.mysql.com/doc/refman/8.0/en/date-and-time-functions.html#function_now), which in MySQL returns the current date and time:
```sql
date_of_joining DATETIME DEFAULT NOW(),
```

##### Primary key
Finally, one of the most important properties is `PRIMARY KEY`, which we can use to uniquely identify each record in the table, referring to all data of a record within a table for relational databases, as previously discussed in the previous section. We can make the `id` column the `PRIMARY KEY` for this table:
```sql
PRIMARY KEY (id)
```

The final `CREATE TABLE` query will be as follows:
```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
```