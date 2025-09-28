The `Metasploit Project` is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute the exploit code. This exploit code can be custom-made by the user or taken from a database containing the latest already discovered and modularized exploits.
The `Metasploit Framework` includes a suite of tools that you can use to test security vulnerabilities, enumerate networks, execute attacks, and evade detection.
![[Pasted image 20250927191136.png]]

The `modules` mentioned are actual exploit proof-of-concepts that have already been developed and tested in the wild and integrated within the framework to provide pentesters with ease of access to different attack vectors for different platforms and services.

## Understanding the Architecture

All the base files related to Metasploit Framework can be found under `/opt/metasploit/modules/exploits/` on my Arch system.

#### Modules
All the modules can be found in `/opt/metasploit/modules`

```shell
ls /opt/metasploit/modules

auxiliary  encoders  evasion  exploits  nops  payloads  post
```

#### Plugins
Plugins offer the pentester more flexibility when using the `msfconsole` since they can easily be manually or automatically loaded as needed to provide extra functionality and automation during our assessment.
#### Scripts
Meterpreter functionality and other useful scripts.

#### Tools
Command-line utilities that can be called directly from the `msfconsole` menu.
