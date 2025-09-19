While brute-forcing can be a fruitful approach, there's a less invasive and potentially more efficient method for uncovering subdomains – DNS zone transfers. This mechanism, designed for replicating DNS records between name servers, can inadvertently become a goldmine of information for prying eyes if misconfigured.

## What is a Zone Transfer

A DNS zone transfer is essentially a wholesale copy of all DNS records within a zone (a domain and its subdomains) from one name server to another.
![Diagram showing data transfer between secondary and primary servers. Includes steps: XML Request, XML Record, loop for retries, XML Report, and AOK (Acknowledgment).](https://mermaid.ink/svg/pako:eNqNkc9qwzAMxl9F-JSx7gV8KISWXcY2aHYYwxdjK39obGWKvBFK333ukg5aGNQnW9b3Q_q-g3LkUWk14mfC6HDb2YZtMBHyGdFR9JanCvkL-WG9vh-4C38FDeX74w52J-0oUHxQRHhjG8ca-W5mXAgy4YqpoXotM8EReygqsSxANZRJWuJOpoXSEw0gC3ku3QTfvlQLfBZh9DeOdbELbCgMPQr-58u1LZsnKEq3j_Tdo28wYJS8iVqpgBxs57PjhxPLKGnzr1E6XzNxb5SJx9xnk1A1Rae0cMKVYkpNq3Rt-zG_0uCtnLM6t6DvhPh5zvM31uMPG8qm-A)

1. `Zone Transfer Request (AXFR)`: The secondary DNS server initiates the process by sending a zone transfer request to the primary server. This request typically uses the AXFR (Full Zone Transfer) type.
2. `SOA Record Transfer`: Upon receiving the request (and potentially authenticating the secondary server), the primary server responds by sending its Start of Authority (SOA) record. The SOA record contains vital information about the zone, including its serial number, which helps the secondary server determine if its zone data is current.
3. `DNS Records Transmission`: The primary server then transfers all the DNS records in the zone to the secondary server, one by one. This includes records like A, AAAA, MX, CNAME, NS, and others that define the domain's subdomains, mail servers, name servers, and other configurations.
4. `Zone Transfer Complete`: Once all records have been transmitted, the primary server signals the end of the zone transfer. This notification informs the secondary server that it has received a complete copy of the zone data.
5. `Acknowledgement (ACK)`: The secondary server sends an acknowledgement message to the primary server, confirming the successful receipt and processing of the zone data. This completes the zone transfer process.

## The Zone Transfer Vulnerability
The information gleaned from an unauthorised zone transfer can be invaluable to an attacker. It reveals a comprehensive map of the target's DNS infrastructure, including:

- `Subdomains`: A complete list of subdomains, many of which might not be linked from the main website or easily discoverable through other means. These hidden subdomains could host development servers, staging environments, administrative panels, or other sensitive resources.
- `IP Addresses`: The IP addresses associated with each subdomain, providing potential targets for further reconnaissance or attacks.
- `Name Server Records`: Details about the authoritative name servers for the domain, revealing the hosting provider and potential misconfigurations.


#### Exploiting Zone Transfers

```shell
$ dig axfr @nsztm1.digi.ninja zonetransfer.me

; <<>> DiG 9.18.12-1~bpo11+1-Debian <<>> axfr @nsztm1.digi.ninja zonetransfer.me
; (1 server found)
;; global options: +cmd
zonetransfer.me.	7200	IN	SOA	nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
zonetransfer.me.	300	IN	HINFO	"Casio fx-700G" "Windows XP"
zonetransfer.me.	301	IN	TXT	"google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
zonetransfer.me.	7200	IN	MX	0 ASPMX.L.GOOGLE.COM.
...
zonetransfer.me.	7200	IN	A	5.196.105.14
zonetransfer.me.	7200	IN	NS	nsztm1.digi.ninja.
zonetransfer.me.	7200	IN	NS	nsztm2.digi.ninja.
_acme-challenge.zonetransfer.me. 301 IN	TXT	"6Oa05hbUJ9xSsvYy7pApQvwCUSSGgxvrbdizjePEsZI"
_sip._tcp.zonetransfer.me. 14000 IN	SRV	0 0 5060 www.zonetransfer.me.
14.105.196.5.IN-ADDR.ARPA.zonetransfer.me. 7200	IN PTR www.zonetransfer.me.
asfdbauthdns.zonetransfer.me. 7900 IN	AFSDB	1 asfdbbox.zonetransfer.me.
asfdbbox.zonetransfer.me. 7200	IN	A	127.0.0.1
asfdbvolume.zonetransfer.me. 7800 IN	AFSDB	1 asfdbbox.zonetransfer.me.
canberra-office.zonetransfer.me. 7200 IN A	202.14.81.230
...
;; Query time: 10 msec
;; SERVER: 81.4.108.41#53(nsztm1.digi.ninja) (TCP)
;; WHEN: Mon May 27 18:31:35 BST 2024
;; XFR size: 50 records (messages 1, bytes 2085)
```


### Questions

1. After performing a zone transfer for the domain inlanefreight.htb on the target system, how many DNS records are retrieved from the target system's name server? Provide your answer as an integer, e.g, 123.
```shell
> dig axfr inlanefreight.htb @10.129.130.142

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> axfr inlanefreight.htb @10.129.130.142
;; global options: +cmd
inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.	604800	IN	NS	ns.inlanefreight.htb.
admin.inlanefreight.htb. 604800	IN	A	10.10.34.2
ftp.admin.inlanefreight.htb. 604800 IN	A	10.10.34.2
careers.inlanefreight.htb. 604800 IN	A	10.10.34.50
dc1.inlanefreight.htb.	604800	IN	A	10.10.34.16
dc2.inlanefreight.htb.	604800	IN	A	10.10.34.11
internal.inlanefreight.htb. 604800 IN	A	127.0.0.1
admin.internal.inlanefreight.htb. 604800 IN A	10.10.1.11
wsus.internal.inlanefreight.htb. 604800	IN A	10.10.1.240
ir.inlanefreight.htb.	604800	IN	A	10.10.45.5
dev.ir.inlanefreight.htb. 604800 IN	A	10.10.45.6
ns.inlanefreight.htb.	604800	IN	A	127.0.0.1
resources.inlanefreight.htb. 604800 IN	A	10.10.34.100
securemessaging.inlanefreight.htb. 604800 IN A	10.10.34.52
test1.inlanefreight.htb. 604800	IN	A	10.10.34.101
us.inlanefreight.htb.	604800	IN	A	10.10.200.5
cluster14.us.inlanefreight.htb.	604800 IN A	10.10.200.14
messagecenter.us.inlanefreight.htb. 604800 IN A	10.10.200.10
ww02.inlanefreight.htb.	604800	IN	A	10.10.34.112
www1.inlanefreight.htb.	604800	IN	A	10.10.34.111
inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 8 msec
;; SERVER: 10.129.130.142#53(10.129.130.142) (TCP)
;; WHEN: Thu Sep 18 19:17:54 CEST 2025
;; XFR size: 22 records (messages 1, bytes 594)
```

2. Within the zone record transferred above, find the ip address for ftp.admin.inlanefreight.htb. Respond only with the IP address, eg 127.0.0.1
```shell
Answer above:
ftp.admin.inlanefreight.htb. 604800 IN	A	10.10.34.2
```

3. Within the same zone record, identify the largest IP address allocated within the 10.10.200 IP range. Respond with the full IP address, eg 10.10.200.1

```shell
Answer above:
cluster14.us.inlanefreight.htb.	604800 IN A	10.10.200.14
```