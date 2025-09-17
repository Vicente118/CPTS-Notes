## Scenario 1: Phishing Investigation
An email security gateway flags a suspicious email sent to multiple employees within a company. The email claims to be from the company's bank and urges recipients to click on a link to update their account information. A security analyst investigates the email and begins by performing a WHOIS lookup on the domain linked in the email.

The WHOIS record reveals the following:

- `Registration Date`: The domain was registered just a few days ago.
- `Registrant`: The registrant's information is hidden behind a privacy service.
- `Name Servers`: The name servers are associated with a known bulletproof hosting provider often used for malicious activities.

This combination of factors raises significant red flags for the analyst.

## Scenario 2: Malware Analysis
A security researcher is analysing a new strain of malware that has infected several systems within a network. The malware communicates with a remote server to receive commands and exfiltrate stolen data. To gain insights into the threat actor's infrastructure, the researcher performs a WHOIS lookup on the domain associated with the command-and-control (C2) server.

The WHOIS record reveals:

- `Registrant`: The domain is registered to an individual using a free email service known for anonymity.
- `Location`: The registrant's address is in a country with a high prevalence of cybercrime.
- `Registrar`: The domain was registered through a registrar with a history of lax abuse policies.

Based on this information, the researcher concludes that the C2 server is likely hosted on a compromised or "bulletproof" server.


## Scenario 3: Threat Intelligence Report
A cybersecurity firm tracks the activities of a sophisticated threat actor group known for targeting financial institutions. Analysts gather WHOIS data on multiple domains associated with the group's past campaigns to compile a comprehensive threat intelligence report.

By analysing the WHOIS records, analysts uncover the following patterns:

- `Registration Dates`: The domains were registered in clusters, often shortly before major attacks.
- `Registrants`: The registrants use various aliases and fake identities.
- `Name Servers`: The domains often share the same name servers, suggesting a common infrastructure.
- `Takedown History`: Many domains have been taken down after attacks, indicating previous law enforcement or security interventions.

## Using WHOIS

```shell-session
$ whois facebook.com
```

The WHOIS output for `facebook.com` reveals several key details:

1. `Domain Registration`:
    - `Registrar`: RegistrarSafe, LLC
    - `Creation Date`: 1997-03-29
    - `Expiry Date`: 2033-03-30
    These details indicate that the domain is registered with RegistrarSafe, LLC, and has been active for a considerable period, suggesting its legitimacy and established online presence. The distant expiry date further reinforces its longevity.
    
2. `Domain Owner`:
    - `Registrant/Admin/Tech Organization`: Meta Platforms, Inc.
    - `Registrant/Admin/Tech Contact`: Domain Admin
    This information identifies Meta Platforms, Inc. as the organization behind `facebook.com`, and "Domain Admin" as the point of contact for domain-related matters. This is consistent with the expectation that Facebook, a prominent social media platform, is owned by Meta Platforms, Inc.
    
3. `Domain Status`:
    - `clientDeleteProhibited`, `clientTransferProhibited`, `clientUpdateProhibited`, `serverDeleteProhibited`, `serverTransferProhibited`, and `serverUpdateProhibited`
    These statuses indicate that the domain is protected against unauthorized changes, transfers, or deletions on both the client and server sides. This highlights a strong emphasis on security and control over the domain.
    
4. `Name Servers`:
    - `A.NS.FACEBOOK.COM`, `B.NS.FACEBOOK.COM`, `C.NS.FACEBOOK.COM`, `D.NS.FACEBOOK.COM`
    These name servers are all within the `facebook.com` domain, suggesting that Meta Platforms, Inc. manages its DNS infrastructure. It is common practice for large organizations to maintain control and reliability over their DNS resolution.


### Questions 

1.  Perform a WHOIS lookup against the paypal.com domain. What is the registrar Internet Assigned Numbers Authority (IANA) ID number?
```shell
> whois paypal.com | grep IANA
Registrar IANA ID: 292

Answer: 292
```

2.  What is the admin email contact for the tesla.com domain (also in-scope for the Tesla bug bounty program)?
```shell
> whois tesla.com | grep  mail
admin@dnstinations.com
```