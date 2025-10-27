As mentioned before, there are five Flexible Single Master Operation (FSMO) roles. These roles can be defined as follows:

| **Roles**                  | **Description**                                                                                                                                                                                                                                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Schema Master`            | This role manages the read/write copy of the AD schema, which defines all attributes that can apply to an object in AD.                                                                                                                                                                                            |
| `Domain Naming Master`     | Manages domain names and ensures that two domains of the same name are not created in the same forest.                                                                                                                                                                                                             |
| `Relative ID (RID) Master` | The RID Master assigns blocks of RIDs to other DCs within the domain that can be used for new objects. The RID Master helps ensure that multiple objects are not assigned the same SID. Domain object SIDs are the domain SID combined with the RID number assigned to the object to make the unique SID.          |
| `PDC Emulator`             | The host with this role would be the authoritative DC in the domain and respond to authentication requests, password changes, and manage Group Policy Objects (GPOs). The PDC Emulator also maintains time within the domain.                                                                                      |
| `Infrastructure Master`    | This role translates GUIDs, SIDs, and DNs between domains. This role is used in organizations with multiple domains in a single forest. The Infrastructure Master helps them to communicate. If this role is not functioning properly, Access Control Lists (ACLs) will show SIDs instead of fully resolved names. |
Depending on the organization, these roles may be assigned to specific DCs or as defaults each time a new DC is added. Issues with FSMO roles will lead to authentication and authorization difficulties within a domain.
## Domain and Forest Functional Levels
Microsoft introduced functional levels to determine the various features and capabilities available in Active Directory Domain Services (AD DS) at the domain and forest level. They are also used to specify which Windows Server operating systems can run a Domain Controller in a domain or forest.
## Trusts
A trust is used to establish `forest-forest` or `domain-domain` authentication, allowing users to access resources in (or administer) another domain outside of the domain their account resides in. A trust creates a link between the authentication systems of two domains.
There are several trust types.

|**Trust Type**|**Description**|
|---|---|
|`Parent-child`|Domains within the same forest. The child domain has a two-way transitive trust with the parent domain.|
|`Cross-link`|a trust between child domains to speed up authentication.|
|`External`|A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering.|
|`Tree-root`|a two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.|
|`Forest`|a transitive trust between two forest root domains.|
#### Trust Example
![[Pasted image 20251025163617.png]]
Trusts can be transitive or non-transitive.
- A transitive trust means that trust is extended to objects that the child domain trusts.
- In a non-transitive trust, only the child domain itself is trusted.

Trusts can be set up to be one-way or two-way (bidirectional).
- In bidirectional trusts, users from both trusting domains can access resources.
- In a one-way trust, only users in a trusted domain can access resources in a trusting domain, not vice-versa. The direction of trust is opposite to the direction of access.