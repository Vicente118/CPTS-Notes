## AND Operator
The result of the `AND` operation is `true` if and only if both `condition1` and `condition2` evaluate to `true`:

```SQL
SELECT 1 = 1 AND 'test' = 'test';
+---------------------------+
| 1 = 1 AND 'test' = 'test' |
+---------------------------+
|                         1 |
+---------------------------+


SELECT 1 = 1 AND 'test' = 'abc';
+--------------------------+
| 1 = 1 AND 'test' = 'abc' |
+--------------------------+
|                        0 |
+--------------------------+
```

In MySQL terms, any `non-zero` value is considered `true`, and it usually returns the value `1` to signify `true`. `0` is considered `false`.

---
## OR Operator
The `OR` operator takes in two expressions as well, and returns `true` when at least one of them evaluates to `true`:
```SQL
SELECT 1 = 1 OR 'test' = 'abc';
+-------------------------+
| 1 = 1 OR 'test' = 'abc' |
+-------------------------+
|                       1 |
+-------------------------+


mysql> SELECT 1 = 2 OR 'test' = 'abc';
+-------------------------+
| 1 = 2 OR 'test' = 'abc' |
+-------------------------+
|                       0 |
+-------------------------+
```

---
## NOT Operator
The `NOT` operator simply toggles a `boolean` value 'i.e. `true` is converted to `false` and vice versa:
```SQL
SELECT NOT 1 = 1;
+-----------+
| NOT 1 = 1 |
+-----------+
|         0 |
+-----------+


SELECT NOT 1 = 2;
+-----------+
| NOT 1 = 2 |
+-----------+
|         1 |
+-----------+
```

---
## Symbol Operators
The `AND`, `OR` and `NOT` operators can also be represented as `&&`, `||` and `!`, respectively. The below are the same previous examples, by using the symbol operators.
```SQL
SELECT 1 = 1 && 'test' = 'abc';
+-------------------------+
| 1 = 1 && 'test' = 'abc' |
+-------------------------+
|                       0 |
+-------------------------+


mysql> SELECT 1 = 1 || 'test' = 'abc';
+-------------------------+
| 1 = 1 || 'test' = 'abc' |
+-------------------------+
|                       1 |
+-------------------------+


mysql> SELECT 1 != 1;
+--------+
| 1 != 1 |
+--------+
|      0 |
+--------+
```
---
## Operators in queries
Let us look at how these operators can be used in queries. The following query lists all records where the `username` is NOT `john`:
```SQL
SELECT * FROM logins WHERE username != 'john';

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
```

The next query selects users who have their `id` greater than `1` AND `username` NOT equal to `john`:
```SQL
SELECT * FROM logins WHERE username != 'john' AND id > 1;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
```

---
## Multiple Operator Precedence
Here is a list of common operations and their precedence, as seen in the [MariaDB Documentation](https://mariadb.com/kb/en/operator-precedence/):
- Division (`/`), Multiplication (`*`), and Modulus (`%`)
- Addition (`+`) and subtraction (`-`)
- Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)

Operations at the top are evaluated before the ones at the bottom of the list. Let us look at an example:
```sql
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
```
The query has four operations: `!=`, `AND`, `>`, and `-`. From the operator precedence, we know that subtraction comes first, so it will first evaluate `3 - 2` to `1`:
```sql
SELECT * FROM logins WHERE username != 'tom' AND id > 1;
```


