There are several ways that we can gather a target list of valid users:
- SMB NULL Session to retrieve a complete list of domain users from the domain controller.
- LDAP anonymous bind to query LDAP anonymously and pull down user list.
- using Kerbrute to validate users utilzing a word list such as [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) or gathered by using tool such as linkedin2username.
-  Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using `Responder` or even a successful password spray using a smaller wordlist

No matter the method we choose, it is also vital for us to consider the domain password policy. If we have an SMB NULL session, LDAP anonymous bind, or a set of valid credentials, we can enumerate the password policy.

