Now that we know how the Union clause works and how to use it let us learn how to utilize it in our SQL injections. Let us take the following example:
![Search interface with a text box and button labeled 'Search'. Below is a table with columns: Port Code, Port City, and Port Volume. Entries include CN SHA, Shanghai, 37.13 and CN SHE, Shenzhen, 23.97](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/33/ports_cn.png)

We see a potential SQL injection in the search parameters. We apply the SQLi Discovery steps by injecting a single quote (`'`), and we do get an error:
![Search interface with a text box and button labeled 'Search'. Below is a table with columns: Port Code, Port City, and Port Volume. An error message states: You have an error in your SQL syntax; check the manual for the right syntax near](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/33/ports_quote.png)

## Detect number of columns
Before going ahead and exploiting Union-based queries, we need to find the number of columns selected by the server. There are two methods of detecting the number of columns:
- Using `ORDER BY`
- Using `UNION`
#### Using ORDER BY
We have to inject a query that sorts the results by a column we specified, 'i.e., column 1, column 2, and so on', until we get an error saying the column specified does not exist.

```sql
' order by 1-- -   -> OK
' order by 2-- -   -> OK
' order by 3-- -   -> OK
' order by 4-- -   -> OK
' order by 5-- -   -> Fail
```
This means there is 4 column in the table

---
#### Using UNION
The other method is to attempt a Union injection with a different number of columns until we successfully get the results back. The first method always returns the results until we hit an error, while this method always gives an error until we get a success. We can start by injecting a 3 column `UNION` query:
```sql
cn' UNION select 1,2,3-- -
```
We get an error saying that the number of columns don’t match:

So, let’s try four columns and see the response:
```sql
cn' UNION select 1,2,3,4-- -
```
![[Pasted image 20251118152616.png]]
So we know this table has 4 column
Once we know the number of columns, we know how to form our payload, and we can proceed to the next step.

---
## Location of Injection
While a query may return multiple columns, the web application may only display some of them. So, if we inject our query in a column that is not printed on the page, we will not get its output.
This is why we need to determine which columns are printed to the page, to determine where to place our injection. In the previous example, while the injected query returned 1, 2, 3, and 4, we saw only 2, 3, and 4 displayed back to us on the page as the output data:
![[Pasted image 20251118152831.png]]
This tells us that columns 2 and 3, and 4 are printed to place our injection in any of them.
`We cannot place our injection at the beginning, or its output will not be printed.`


```sql
cn' UNION select 1,@@version,3,4-- -
```
![[Pasted image 20251118152906.png]]

```sql
cn' UNION select 1,user(),3,4-- -
```
-> root@localhost
