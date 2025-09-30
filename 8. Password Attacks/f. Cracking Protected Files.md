 In many cases, `symmetric encryption` algorithms such as `AES-256` are used to securely store individual files or folders. In this method, the same key is used for both encryption and decryption.

For transmitting files, `asymmetric encryption` is typically employed, which uses two distinct keys: the sender encrypts the file with the recipient's `public key`, and the recipient decrypts it using the corresponding `private key`.

## Hunting for Encrypted Files
Many different extensions correspond to encrypted files—a useful reference list can be found on [FileInfo](https://fileinfo.com/filetypes/encoded). As an example, consider this command we might use to locate commonly encrypted files on a Linux system:

```shell
for ext in $(echo ".xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```
This commands makes a loop in each of the known extensions and try to find files that contains thoses extensions in the file system.  

## Hunting for SSH keys
Certain files, such as SSH keys, do not have standard file extension. In cases like these, it may be possible to identify files by standard content such as header and footer values. For example, SSH private keys always begin with `-----BEGIN [...SNIP...] PRIVATE KEY-----`. We can use tools like `grep` to recursively search the file system for them during post-exploitation.

```shell
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
```
Some SSH keys are encrypted with a passphrase. With older PEM formats, it was possible to tell if an SSH key is encrypted based on the header, which contains the encryption method in use. Modern SSH keys, however, appear the same whether encrypted or not.

```shell=
cat /home/jsmith/.ssh/SSH.private

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2109D25CC91F8DBFCEB0F7589066B2CC

8Uboy0afrTahejVGmB7kgvxkqJLOczb1I0/hEzPU1leCqhCKBlxYldM2s65jhflD
4/OH4ENhU7qpJ62KlrnZhFX8UwYBmebNDvG12oE7i21hB/9UqZmmHktjD3+OYTsD
<SNIP>
```

One way to tell whether an SSH key is encrypted or not, is to try reading the key with `ssh-keygen`.
```shell
$ ssh-keygen -yf ~/.ssh/id_ed25519 

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpNefJd834VkD5iq+22Zh59Gzmmtzo6rAffCx2UtaS6
```
As shown below, attempting to read a password-protected SSH key will prompt the user for a passphrase:
```shell
ssh-keygen -yf ~/.ssh/id_rsa

Enter passphrase for "/home/jsmith/.ssh/id_rsa":
```

## Cracking encrypted SSH keys

```shell
> ssh2john.py SSH.private > ssh.hash
> john --wordlist=rockyou.txt ssh.hash


1234         (SSH.private)
```

## Cracking password-protected documents
Today, most reports, documentation, and information sheets are commonly distributed as Microsoft Office documents or PDFs. John the Ripper (JtR) includes a Python script called `office2john.py`, which can be used to extract password hashes from all common Office document formats. These hashes can then be supplied to JtR or Hashcat for offline cracking. The cracking procedure remains consistent with other hash types.

```shell-session
office2john.py Protected.docx > protected-docx.hash
john --wordlist=rockyou.txt protected-docx.hash
john protected-docx.hash --show

Protected.docx:1234

1 password hash cracked, 0 left
```


### Question

1. Download the attached ZIP archive (cracking-protected-files.zip), and crack the file within. What is the password?

```shell
Let's crack this file Confidential.xlsx.

> office2john.py Confidential.xlsx > office.hash 
> john --wordlist=`fzf-wordlists` office.hash 
beethoven        (Confidential.xlsx)
```