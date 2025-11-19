## INSERT Statement
```sql
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
```
```SQL
INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');
```

 However, we can skip filling columns with default values, such as `id` and `date_of_joining`. This can be done by specifying the column names to insert values into a table selectively:
 ```sql
INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
```
```SQL
INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');
```

We can also insert multiple records at once by separating them with a comma:
```SQL
INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
```

---
## SELECT Statement
The general syntax to view the entire table is as follows:
```sql
SELECT * FROM table_name;
```

```sql
SELECT column1, column2 FROM table_name;
```

---
## DROP Statement
We can use [DROP](https://dev.mysql.com/doc/refman/8.0/en/drop-table.html) to remove tables and databases from the server.
```SQL
DROP TABLE logins;
```

---
## ALTER Statement
Finally, We can use [ALTER](https://dev.mysql.com/doc/refman/8.0/en/alter-table.html) to change the name of any table and any of its fields or to delete or add a new column to an existing table. The below example adds a new column `newColumn` to the `logins` table using `ADD`:

#### ADD COLUMN
```SQL
ALTER TABLE logins ADD newColumn INT;
```

#### RENAME COLUMN
```SQL
ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;
```

#### MODIFY COLUMN
```SQL
ALTER TABLE logins MODIFY newerColumn DATE;
```

#### DELETE COLUMN
```SQL
ALTER TABLE logins DROP newerColumn;
```

---
## UPDATE Statement
While `ALTER` is used to change a table's properties, the [UPDATE](https://dev.mysql.com/doc/refman/8.0/en/update.html) statement can be used to update specific records within a table, based on certain conditions. Its general syntax is:
```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```

Exemple:
```SQL
UPDATE logins SET password = 'change_password' WHERE id > 1;
```