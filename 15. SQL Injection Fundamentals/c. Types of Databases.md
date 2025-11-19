## Relational Databases
Tables in a relational database are associated with keys that provide a quick database summary or access to the specific row or column when specific data needs to be reviewed. These tables, also called entities, are all related to each other. For example, the customer information table can provide each customer with a specific ID that can indicate everything we need to know about that customer, such as an address, name, and contact information. Also, the product description table can assign a specific ID to each product. The table that stores all orders would only need to record these IDs and their quantity. Any change in these tables will affect all of them but predictably and systematically.

However, when processing an integrated database, a concept is required to link one table to another using its key, called a `relational database management system` (`RDBMS`). Many companies that initially use different concepts are switching to the RDBMS concept because this concept is easy to learn, use and understand. Initially, this concept was used only by large companies. However, many types of databases now implement the RDBMS concept, such as Microsoft Access, MySQL, SQL Server, Oracle, PostgreSQL, and many others.

For example, we can have a `users` table in a relational database containing columns like `id`, `username`, `first_name`, `last_name`, and others. The `id` can be used as the table key. Another table, `posts`, may contain posts made by all users, with columns like `id`, `user_id`, `date`, `content`, and so on.
![[Pasted image 20251118111958.png]]
We can link the `id` from the `users` table to the `user_id` in the `posts` table to retrieve the user details for each post without storing all user details with each post. A table can have more than one key, as another column can be used as a key to link with another table.
The relationship between tables within a database is called a Schema.

---
## Non-relational Databases
A non-relational database (also called a `NoSQL` database) does not use tables, rows, and columns or prime keys, relationships, or schemas. Instead, a NoSQL database stores data using various storage models, depending on the type of data stored. Due to the lack of a defined structure for the database, NoSQL databases are very scalable and flexible. Therefore, when dealing with datasets that are not very well defined and structured, a NoSQL database would be the best choice for storing such data. There are four common storage models for NoSQL databases:
- Key-Value
- Document-Based
- Wide-Column
- Graph

Each of the above models has a different way of storing data. For example, the `Key-Value` model usually stores data in JSON or XML, and have a key for each pair, and stores all of its data as its value:
![[Pasted image 20251118112214.png]]

The above example can be represented using JSON as
```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

