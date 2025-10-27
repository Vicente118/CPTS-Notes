The final assessment for this module is the execution of `two` internal penetration tests against the company Inlanefreight.
## Assessment Scope
The following `IPs`, `hosts`, and `domains` defined below make up the scope of the assessment.
#### In Scope For Assessment
|**Range/Domain**|**Description**|
|---|---|
|`INLANEFREIGHT.LOCAL`|Customer domain to include AD and web services.|
|`LOGISTICS.INLANEFREIGHT.LOCAL`|Customer subdomain|
|`FREIGHTLOGISTICS.LOCAL`|Subsidiary company owned by Inlanefreight. External forest trust with INLANEFREIGHT.LOCAL|
|`172.16.5.0/23`|In-scope internal subnet.|
#### Out Of Scope
- `Any other subdomains of INLANEFREIGHT.LOCAL`
- `Any subdomains of FREIGHTLOGISTICS.LOCAL`
- `Any phishing or social engineering attacks`
- `Any other IPS/domains/subdomains not explicitly mentioned`
- `Any types of attacks against the real-world inlanefreight.com website outside of passive enumeration shown in this module`

## Methods Used
The following methods are authorized for assessing Inlanefreight and its systems :

### External Information Gathering (Passive Checks)
External information gathering is authorized to demonstrate the risks associated with information that can be gathered about the company from the internet. To simulate a real-world attack, CAT-5 and its assessors will conduct external information gathering from an anonymous perspective on the internet with no information provided in advance regarding Inlanefreight outside of what is provided within this document.

Cat-5 will perform passive enumeration to uncover information that may help with internal testing. Testing will employ various degrees of information gathering from open-source resources to identify publicly accessible data that may pose a risk to Inlanefreight and assist with the internal penetration test. No active enumeration, port scans, or attacks will be performed against internet-facing "real-world" IP addresses or the website located at `https://www.inlanefreight.com`.

### Internal Testing
The internal assessment portion is designed to demonstrate the risks associated with vulnerabilities on internal hosts and services ( `Active Directory specifically`) by attempting to emulate attack vectors from within Inlanefreight's area of operations. The result will allow Inlanefreight to assess the risks of internal vulnerabilities and the potential impact of a successfully exploited vulnerability.

To simulate a real-world attack, Cat-5 will conduct the assessment from an untrusted insider perspective with no advance information outside of what's provided in this documentation and discovered from external testing. Testing will start from an anonymous position on the internal network with the goal of obtaining domain user credentials, enumerating the internal domain, gaining a foothold, and moving laterally and vertically to achieve compromise of all in-scope internal domains. Computer systems and network operations will not be intentionally interrupted during the test.

### Password Testing
Password files captured from Inlanefreight devices, or provided by the organization, may be loaded onto offline workstations for decryption and utilized to gain further access and accomplish the assessment goals. At no time will a captured password file or the decrypted passwords be revealed to persons not officially participating in the assessment. All data will be stored securely on Cat-5 owned and approved systems and retained for a period of time defined in the official contract between Cat-5 and Inlanefreight.
