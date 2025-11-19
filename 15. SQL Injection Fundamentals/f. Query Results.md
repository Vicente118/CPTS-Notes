## Sorting Results
```SQl
SELECT * FROM logins ORDER BY password;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
```

By default, the sort is done in ascending order, but we can also sort the results by `ASC` or `DESC`:
```SQL
SELECT * FROM logins ORDER BY password DESC;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
+----+---------------+------------+---------------------+
```

It is also possible to sort by multiple columns, to have a secondary sort for duplicate values in one column:
```shell
SELECT * FROM logins ORDER BY password DESC, id ASC;
```

---
## LIMIT results
In case our query returns a large number of records, we can [LIMIT](https://dev.mysql.com/doc/refman/8.0/en/limit-optimization.html) the results to what we want only, using `LIMIT` and the number of records we want:
```SQL
SELECT * FROM logins LIMIT 2;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
+----+---------------+------------+---------------------+
```

If we wanted to LIMIT results with an offset, we could specify the offset before the LIMIT count:
```SQL
SELECT * FROM logins LIMIT 1, 2;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
```

---
## WHERE Clause
To filter or search for specific data, we can use conditions with the `SELECT` statement using the [WHERE](https://dev.mysql.com/doc/refman/8.0/en/where-optimization.html) clause, to fine-tune the results:
```sql
SELECT * FROM table_name WHERE <condition>;
```

The query above will return all records which satisfy the given condition. Let us look at an example:
```SQL
SELECT * FROM logins WHERE id > 1;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
```

We can do something similar for usernames:
```SQL
SELECT * FROM logins where username = 'admin';

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
+----+----------+----------+---------------------+
```

---
## LIKE Clause
Another useful SQL clause is [LIKE](https://dev.mysql.com/doc/refman/8.0/en/pattern-matching.html), enabling selecting records by matching a certain pattern. The query below retrieves all records with usernames starting with `admin`:
```SQL
SELECT * FROM logins WHERE username LIKE 'admin%';

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  4 | administrator | adm1n_p@ss | 2020-07-02 15:19:02 |
+----+---------------+------------+---------------------+
```


The `%` symbol acts as a wildcard and matches all characters after `admin`. It is used to match zero or more characters. Similarly, the `_` symbol is used to match exactly one character. The below query matches all usernames with exactly three characters in them, which in this case was `tom`:
```SQL
SELECT * FROM logins WHERE username like '___';

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  3 | tom      | tom123!  | 2020-07-02 15:18:56 |
+----+----------+----------+---------------------+
```


### Question
1. What is the last name of the employee whose first name starts with "Bar" AND who was hired on 1990-01-01?
```SQL
SELECT last_name,hire_date FROM employees WHERE first_name LIKE 'Bar%' AND hire_date = '1990-01-01';

+-----------+------------+
| last_name | hire_date  |
+-----------+------------+
| Mitchem   | 1990-01-01 |
+-----------+------------+
```