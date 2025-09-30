Besides standalone files, we will often run across `archives` and `compressed files`—such as ZIP files—which are protected with a password.
There are many types of archive files. Some of the more commonly encountered file extensions include `tar`, `gz`, `rar`, `zip`, `vmdb/vmx`, `cpt`, `truecrypt`, `bitlocker`, `kdbx`, `deb`, `7z`, and `gzip`.

## Cracking ZIP files

```shell
zip2john ZIP.zip > zip.hash
V0xD0x@htb[/htb]$ cat zip.hash 

ZIP.zip/customers.csv:$pkzip2$1*2*2*0*2a*1e*490e7510*0*42*0*2a*490e*409b*ef1e7feb7c1cf701a6ada7132e6a5c6c84c032401536faf7493df0294b0d5afc3464f14ec081cc0e18cb*$/pkzip2$:customers.csv:ZIP.zip::ZIP.zip
```

```shell
> john --wordlist=rockyou.txt zip.hash

> john zip.hash --show
ZIP.zip/customers.csv:1234:customers.csv:ZIP.zip::ZIP.zip
```

## Cracking OpenSSL encrypted GZIP files
It is not always immediately apparent whether a file is password-protected, particularly when the file extension corresponds to a format that does not natively support password protection. As previously discussed, `openssl` can be used to encrypt files in the `GZIP` format. To determine the actual format of a file, we can use the `file` command, which provides detailed information about its contents. For example:
```shell
> file GZIP.gzip 

GZIP.gzip: openssl enc'd data with salted password
```

When cracking OpenSSL encrypted files, we may encounter various challenges, including numerous false positives or complete failure to identify the correct password. To mitigate this, a more reliable approach is to use the `openssl` tool within a `for` loop that attempts to extract the contents directly, succeeding only if the correct password is found.
The following one-liner may produce several GZIP-related error messages, which can be safely ignored. If the correct password list is used, as in this example, we will see another file successfully extracted from the archive.

```shell
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```

Once the `for` loop has finished, we can check the current directory for a newly extracted file.

## Cracking BitLocker-encrypted drives
[BitLocker](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-device-encryption-overview-windows-10) is a full-disk encryption feature developed by Microsoft for the Windows operating system. Available since Windows Vista, it uses the `AES` encryption algorithm with either 128-bit or 256-bit key lengths. If the password or PIN used for BitLocker is forgotten, decryption can still be performed using a recovery key—a 48-digit string generated during the setup process.

To crack a BitLocker encrypted drive, we can use a script called `bitlocker2john` to [four different hashes](https://openwall.info/wiki/john/OpenCL-BitLocker): the first two correspond to the BitLocker password, while the latter two represent the recovery key. Because the recovery key is very long and randomly generated, it is generally not practical to guess—unless partial knowledge is available. Therefore, we will focus on cracking the password using the first hash (`$bitlocker$0$...`).

```shell
> bitlocker2john -i Backup.vhd > backup.hashes
> grep "bitlocker\$0" backup.hashes > backup.hash
> cat backup.hash

$bitlocker$0$16$02b329c0453b9273f2fc1b927443b5fe$1048576$12$00b0a67f961dd80103000000$60$d59f37e70696f7eab6b8f95ae93bd53f3f7067d5e33c0394b3d8e2d1fdb885cb86c1b978f6cc12ed26de0889cd2196b0510bbcd2a8c89187ba8ec54f
```
Once a hash is generated, either `JtR` or `hashcat` can be used to crack it. For this example, we will look at the procedure with `hashcat`. The hashcat mode associated with the `$bitlocker$0$...` hash is `-m 22100`.

```shell
hashcat -a 0 -m 22100 '$bitlocker$0$16$02b329c0453b9273f2fc1b927443b5fe$1048576$12$00b0a67f961dd80103000000$60$d59f37e70696f7eab6b8f95ae93bd53f3f7067d5e33c0394b3d8e2d1fdb885cb86c1b978f6cc12ed26de0889cd2196b0510bbcd2a8c89187ba8ec54f' /usr/share/wordlists/rockyou.txt
```

#### Mounting BitLocker-encrypted drives in Windows
The easiest method for mounting a BitLocker-encrypted virtual drive on Windows is to double-click the `.vhd` file. Since it is encrypted, Windows will initially show an error. After mounting, simply double-click the BitLocker volume to be prompted for the password.
![[Pasted image 20250929163700.png]]

#### Mounting BitLocker-encrypted drives in Linux (or macOS)

1. Install `dislocker` amd `losetup`
2. Create 2 folders which we will use to mount the VHD.

```shell
sudo mkdir -p /media/bitlocker
sudo mkdir -p /media/bitlockermount
```

3.  We then use `losetup` to configure the VHD as [loop device](https://en.wikipedia.org/wiki/Loop_device), decrypt the drive using `dislocker`, and finally mount the decrypted volume:

```shell
sudo losetup -f -P Backup.vhd
sudo losetup (To see wich loop is associated to our .vhd)
lsblk (To know exactly the partition name)
sudo dislocker /dev/loop7p1 -u1234qwer -- /media/bitlocker
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
```

4. If everything was done correctly, we can now browse the files:

```shell
cd /media/bitlockermount/
```

Once we have analyzed the files on the mounted drive, we can unmount it using the following commands:

```shell
sudo umount /media/bitlockermount
sudo umount /media/bitlocker
```


### Questions 

Target: 94.237.123.178:59248

1.  Run the above target then navigate to http://ip:port/download, then extract the downloaded file. Inside, you will find a password-protected VHD file. Crack the password for the VHD and submit the recovered password as your answer.
2.  Mount the BitLocker-encrypted VHD and enter the contents of flag.txt as your answer.

```shell
Cracking of the Private.vhd file like above:
$bitlocker$0$16$b3c105c7ab7faaf544e84d712810da65$1048576$12$b020fe18bbb1db0103000000$60$e9c6b548788aeff190e517b0d85ada5daad7a0a3f40c4467307011ac17f79f8c99768419903025fd7072ee78b15a729afcf54b8c2e3af05bb18d4ba0:francisco

Mounting volume like above:
43d95aeed3114a53ac66f01265f9b7af
```