## Password policy
A [password policy](https://en.wikipedia.org/wiki/Password_policy) is a set of rules designed to enhance computer security by encouraging users to create strong passwords and use them appropriately according to the organization's standards.
The scope of a password policy extends beyond minimum password requirements to encompass the entire password lifecycle (such as creation, storage, management, and transmission).

#### Password policy standards

Some security standards include sections on password policies or guidelines. Here are a few of the most common:
- [NIST SP800-63B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf)
- [CIS Password Policy Guide](https://www.cisecurity.org/insights/white-papers/cis-password-policy-guide)
- [PCI DSS](https://www.pcisecuritystandards.org/document_library?category=pcidss&document=pci_dss)

These standards offer different perspectives on password security. We can study them to help shape our own password policy. Let's examine a use-case where standards differ significantly: `password expiration`.

In the past, we may have heard phrases such as `"change your password every 90 days to stay secure."` The truth is that not every organization follows this—some only required password changes in the event of a confirmed compromise. Today, the industry has shifted to recommending that password expiration be disabled, as it often leads users to adopt predictable, weak patterns.

#### Sample password policy
To illustrate important considerations, here is a sample password policy. It requires that all passwords:
- Minimum of 8 characters.
- Include uppercase and lowercase letters.
- Include at least one number.
- Include at least one special character.
- It should not be the username.
- It should be changed every 60 days.

Our new employee, Mark, who initially received an error when trying to set his email password to `password123`, now chooses `Inlanefreight01!` and successfully registers his account. While this password meets the company's policy requirements, it is still weak and easily guessable, as it includes the company name.

Based on this example, we should include certain blacklisted words in our password policies. These may include, but are not limited to:
- The company's name
- Common words associated with the company
- Names of months
- Names of seasons
- Variations on the words "welcome" and "password"
- Common and easily guessable words such as "password", "123456", and "abcde"

## Enforcing password policy
To implement this policy effectively, it must be enforced using the technology at our disposal or by acquiring the necessary tools. Most applications and identity management systems offer features to support the enforcement of such policies.

For instance, if we use Active Directory for authentication, we can configure an [Active Directory Password Policy GPO](https://activedirectorypro.com/how-to-configure-a-domain-password-policy/) to ensure users comply with our policy.

## Creating a strong password
Creating a strong password doesn't have to be difficult. Tools like [PasswordMonster](https://www.passwordmonster.com/) help evaluate the strength of passwords, while [1Password Password Generator](https://1password.com/password-generator/) can generate secure ones.
