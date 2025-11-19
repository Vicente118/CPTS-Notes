Many organizations implement policies requiring users to change their passwords periodically to enhance security. However, these policies can inadvertently breed predictable password patterns if users are not adequately educated on proper password hygiene.![[Pasted image 20251117115428.png]]

### Hybrid Attacks in Action
Let's illustrate this with a practical example. Consider an attacker targeting an organization known to enforce regular password changes.
![[Pasted image 20251117120947.png]]The attacker begins by launching a dictionary attack, using a wordlist curated with common passwords, industry-specific terms, and potentially personal information related to the organization or its employees. This phase attempts to quickly identify any low-hanging fruit - accounts protected by weak or easily guessable passwords.

However, if the dictionary attack proves unsuccessful, the hybrid attack seamlessly transitions into a brute-force mode. Instead of randomly generating password combinations, it strategically modifies the words from the original wordlist, appending numbers, special characters, or even incrementing years, as in our "Summer2023" example.

---
Let's consider a scenario where you have access to a common passwords wordlist, and you're targeting an organization with the following password policy:
- Minimum length: 8 characters
- Must include:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number

We are going to use the [darkweb2017-top10000.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/darkweb2017_top-10000.txt) password list for this. First, download the wordlist
Next, we need to start matching that wordlist to the password policy.
```shell
grep -E '^.{8,}$' darkweb2017-top10000.txt > darkweb2017-minlength.txt
```
The regular expression `^.{8,}$` acts as a filter, ensuring that only passwords containing at least 8 characters are passed through and saved in a temporary file named `darkweb2017-minlength.txt`.

```shell
grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt
```
 The regular expression `[A-Z]` ensures that any password lacking an uppercase letter is discarded, further refining the list saved in `darkweb2017-uppercase.txt`.

```shell
grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt
```
The regular expression `[a-z]` serves as the filter, keeping only passwords that include at least one lowercase letter and storing them in `darkweb2017-lowercase.txt`.

```shell
grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt
```
The regular expression `[0-9]` acts as a filter, ensuring that passwords containing at least one numerical digit are preserved in `darkweb2017-number.txt`.

---
## Credential Stuffing: Leveraging Stolen Data for Unauthorized Access
![[Pasted image 20251117121422.png]]


