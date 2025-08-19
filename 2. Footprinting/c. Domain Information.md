Domain information is a core component of any penetration test, and it is not just about the subdomains but about the entire presence on the Internet. Therefore, we gather information and try to understand the company's functionality and which technologies and structures are necessary for services to be offered successfully and efficiently.

--- 

#### Subdomains and IPs

This commands is used to find subdomains:

```bash
curl -s https://crt.sh/\?q\=DOMAIN\&output\=json | jq .

Full command:
curl -s https://crt.sh/\?q\=DOMAIN\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u

Associate ip to each subdomains:
for i in $(cat subdomainlist.txt);do host $i | grep "has address" | grep DOMAIN | cut -d" " -f1,4;done

Put this in shodan to get inforations about thoses ips:
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

---

#### DNS Records

```bash
dig any DOMAIN
```

A records: 
- We recognize the IP addresses that point to a specific (sub)domain through the A record. Here we only see one that we already know.

MX records: 
- The mail server records show us which mail server is responsible for managing the emails for the company. Since this is handled by google in our case, we should note this and skip it for now.

NS records: 
- These kinds of records show which name servers are used to resolve the FQDN to IP addresses. Most hosting providers use their own name servers, making it easier to identify the hosting provider.

TXT records: 
- This type of record often contains verification keys for different third-party providers and other security aspects of DNS, such as SPF, DMARC, and DKIM, which are responsible for verifying and confirming the origin of the emails sent. Here we can already see some valuable information if we look closer at the results.
