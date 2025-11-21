~In most cases, SQLMap should run out of the box with the provided target details. Nevertheless, there are options to fine-tune the SQLi injection attempts to help SQLMap in the detection phase. Every payload sent to the target consists of:
- vector (e.g., `UNION ALL SELECT 1,2,VERSION()`): central part of the payload, carrying the useful SQL code to be executed at the target.
- boundaries (e.g. `'<vector>-- -`): prefix and suffix formations, used for proper injection of the vector into the vulnerable SQL statement.
## Prefix/Suffix
There is a requirement for special prefix and suffix values in rare cases, not covered by the regular SQLMap run.  
For such runs, options `--prefix` and `--suffix` can be used as follows:
```bash
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

This will result in an enclosure of all vector values between the static prefix `%'))` and the suffix `-- -`.  
For example, if the vulnerable code at the target is:
```php
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
$result = mysqli_query($link, $query);
```
The vector `UNION ALL SELECT 1,2,VERSION()`, bounded with the prefix `%'))` and the suffix `-- -`, will result in the following (valid) SQL statement at the target:
```sql
SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

## Level/Risk
By default, SQLMap combines a predefined set of most common boundaries (i.e., prefix/suffix pairs), along with the vectors having a high chance of success in case of a vulnerable target. Nevertheless, there is a possibility for users to use bigger sets of boundaries and vectors, already incorporated into the SQLMap.

For such demands, the options `--level` and `--risk` should be used:
- The option `--level` (`1-5`, default `1`) extends both vectors and boundaries being used, based on their expectancy of success (i.e., the lower the expectancy, the higher the level).
- The option `--risk` (`1-3`, default `1`) extends the used vector set based on their risk of causing problems at the target side (i.e., risk of database entry loss or denial-of-service).

As for the number of payloads, by default (i.e. `--level=1 --risk=1`), the number of payloads used for testing a single parameter goes up to 72, while in the most detailed case (`--level=5 --risk=3`) the number of payloads increases to 7,865

In special cases of SQLi vulnerabilities, where usage of `OR` payloads is a must (e.g., in case of `login` pages), we may have to raise the risk level.

## Advanced Tuning
#### Status Codes
For example, when dealing with a huge target response with a lot of dynamic content, subtle differences between `TRUE` and `FALSE` responses could be used for detection purposes. If the difference between `TRUE` and `FALSE` responses can be seen in the HTTP codes (e.g. `200` for `TRUE` and `500` for `FALSE`), the option `--code` could be used to fixate the detection of `TRUE` responses to a specific HTTP code (e.g. `--code=200`).
#### Titles
If the difference between responses can be seen by inspecting the HTTP page titles, the switch `--titles` could be used to instruct the detection mechanism to base the comparison based on the content of the HTML tag `<title>`.
#### Strings
In case of a specific string value appearing in `TRUE` responses (e.g. `success`), while absent in `FALSE` responses, the option `--string` could be used to fixate the detection based only on the appearance of that single value (e.g. `--string=success`).
#### Text-only
When dealing with a lot of hidden content, such as certain HTML page behaviors tags (e.g. `<script>`, `<style>`, `<meta>`, etc.), we can use the `--text-only` switch, which removes all the HTML tags, and bases the comparison only on the textual (i.e., visible) content.
#### Techniques
In some special cases, we have to narrow down the used payloads only to a certain type. For example, if the time-based blind payloads are causing trouble in the form of response timeouts, or if we want to force the usage of a specific SQLi payload type, the option `--technique` can specify the SQLi technique to be used.
For example, if we want to skip the time-based blind and stacking SQLi payloads and only test for the boolean-based blind, error-based, and UNION-query payloads, we can specify these techniques with `--technique=BEU`.
#### UNION SQLi Tuning
In some cases, `UNION` SQLi payloads require extra user-provided information to work. If we can manually find the exact number of columns of the vulnerable SQL query, we can provide this number to SQLMap with the option `--union-cols` (e.g. `--union-cols=17`). In case that the default "dummy" filling values used by SQLMap -`NULL` and random integer- are not compatible with values from results of the vulnerable SQL query, we can specify an alternative value instead (e.g. `--union-char='a'`).

Furthermore, in case there is a requirement to use an appendix at the end of a `UNION` query in the form of the `FROM <table>` (e.g., in case of Oracle), we can set it with the option `--union-from` (e.g. `--union-from=users`).  
Failing to use the proper `FROM` appendix automatically could be due to the inability to detect the DBMS name before its usage.


Lab solutions:
```bash
1. sqlmap -r req -T flag5 --level=5 --risk=3 --dump
2. sqlmap -u http://83.136.254.84:45338/case6.php\?col\=id --batch --dump --prefix='`' --risk=3
3. sqlmap -u "http://83.136.254.84:45338/case7.php?id=1" --batch --dump --union-cols=5 --risk=3 --no-cast
```