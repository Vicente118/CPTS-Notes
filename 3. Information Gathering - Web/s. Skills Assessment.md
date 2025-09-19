### Context

To complete the skills assessment, answer the questions below. You will need to apply a variety of skills learned in this module, including:

- Using `whois`
- Analysing `robots.txt`
- Performing subdomain bruteforcing
- Crawling and analysing results

Demonstrate your proficiency by effectively utilizing these techniques. Remember to add subdomains to your `hosts` file as you discover them.

### Questions 

vHosts needed for these questions:
- `inlanefreight.htb`

1.  What is the IANA ID of the registrar of the inlanefreight.com domain?
2.  What http server software is powering the inlanefreight.htb site on the target system? Respond with the name of the software, not the version, e.g., Apache.
3.  What is the API key in the hidden admin directory that you have discovered on the target system?
4.  After crawling the inlanefreight.htb domain on the target system, what is the email address you have found? Respond with the full email, e.g., mail@inlanefreight.htb.
5. What is the API key the inlanefreight.htb developers will be changing too?

### Solution

Target(s): 94.237.53.63:37855

First let's add inlanefreight.htb to our host file.

```shell
> whois inlanefreight.com | grep IANA
Registrar IANA ID: 468

Answer 1. : 468
```

```shell
> curl -I http://inlanefreight.htb:37855
HTTP/1.1 200 OK
Server: nginx/1.26.1
Date: Fri, 19 Sep 2025 17:12:39 GMT
Content-Type: text/html
Content-Length: 120
Last-Modified: Thu, 01 Aug 2024 09:35:23 GMT
Connection: keep-alive
ETag: "66ab56db-78"
Accept-Ranges: bytes

Answer 2. : nginx
```

```shell
Let's FUZZ subdomains:
> gobuster vhost -u http://inlanefreight.htb:37855 -w `fzf-wordlists` --append-domain
Found: web1337.inlanefreight.htb:37855 Status: 200
Add the new vhost to our hosts file.

> curl http://web1337.inlanefreight.htb:37855/robots.txt
User-agent: *
Allow: /index.html
Allow: /index-2.html
Allow: /index-3.html
Disallow: /admin_h1dd3n

> curl http://web1337.inlanefreight.htb:37855/admin_h1dd3n/
Welcome to web1337 admin site</h1><h2>The admin panel is currently under maintenance, but the API is still accessible with the key e963d863ee0e82ba7080fbf558ca0d3f

Answer 3. : e963d863ee0e82ba7080fbf558ca0d3f
```

```shell
Fuzz vhost once whith new subdomain:
> gobuster vhost -u http://web1337.inlanefreight.htb:37855 -w `fzf-wordlists` --append-domain
Found: dev.web1337.inlanefreight.htb:37855 Status: 200

Crawl this subdomain:
> python3 ReconSpider.py http://dev.web1337.inlanefreight.htb:37855/

Result is in result.json

> cat results.json | grep -n2 mail
1-{
2:    "emails": [
3-        "1337testing@inlanefreight.htb"
4-    ],

Answer 4. : 1337testing@inlanefreight.htb

> cat results.json | grep -i api
"<!-- Remember to change the API key to ba988b835be4aa97d068941dc852ff33 -->"

Answer 5. : ba988b835be4aa97d068941dc852ff33
```