This section explores ways to detect active shells, look for payloads on a host and over network traffic, and how these attacks can be obfuscated to bypass our defenses.

## Monitoring
Before talking about data sources and tools we can use, let's take a second to talk about the [MITRE ATT&CK Framework](https://attack.mitre.org/) and define the techniques and tactics being utilized by attackers. The `ATT&CK Framework` as defined by MITRE, is "`a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations`."

#### ATT&CK Framework
![[Pasted image 20250927173837.png]]

#### Notable MITRE ATT&CK Tactics and Techniques:
|**Tactic / Technique**|**Description**|
|---|---|
|[Initial Access](https://attack.mitre.org/techniques/T1190/)|Attackers will attempt to gain initial access by compromising a public-facing host or service such as web Applications, misconfigured services such as SMB or authentication protocols, and/or bugs in a public-facing host that introduce a vulnerability. This is often done on some form of bastion host and provides the attacker with a foothold in the network but not yet full access. For more information on initial access, especially via Web Applications, check out the [OWASP Top Ten](https://owasp.org/www-project-top-ten/) or read further in the Mitre Att&ck framework.|
|[Execution](https://attack.mitre.org/tactics/TA0002)|This technique depends on code supplied and planted by an attacker running on the victim host. `The Shells & Payloads` module focuses mainly on this tactic. We utilize many different payloads, delivery methods, and shell scripting solutions to access a host. This can be anything from the execution of commands within our web browser to get execution and access on a Web Application, issuing a PowerShell one-liner via PsExec, taking advantage of a publicly released exploit or zero-day in conjunction with a framework such as Metasploit, or uploading a file to a host via many different protocols and calling it remotely to receive a callback.|
|[Command & Control](https://attack.mitre.org/tactics/TA0011)|Command and Control (`C2`) can be looked at as the culmination of our efforts within this module. We gain access to a host and establish some mechanism for continued and/or interactive access via code execution, then utilize that access to perform follow on actions on objectives within the victim network. The use of standard ports and protocols within the victim network to issue commands and receive output from the victim is common. This can appear as anything from normal web traffic over HTTP/S, commands issued via other common external protocols such as DNS and NTP, and even the use of common allowed applications such as Slack, Discord, or MS Teams to issue commands and receive check-ins. C2 can have various levels of sophistication varying from basic clear text channels like Netcat to utilizing encrypted and obfuscated protocols along with complex traffic routes via proxies, redirectors, and VPNs.|
## Events To Watch For:

- `File uploads`: Especially with Web Applications, file uploads are a common method of acquiring a shell on a host besides direct command execution in the browser. Pay attention to application logs to determine if anyone has uploaded anything potentially malicious. The use of firewalls and anti-virus can add more layers to your security posture around the site. Any host exposed to the internet from your network should be sufficiently hardened and monitored.
    
- `Suspicious non-admin user actions`: Looking for simple things like normal users issuing commands via Bash or cmd can be a significant indicator of compromise. When was the last time an average user, much less an admin, had to issue the command `whoami` on a host? Users connecting to a share on another host in the network over SMB that is not a normal infrastructure share can also be suspicious. This type of interaction usually is end host to infrastructure server, not end host to end host. Enabling security measures such as logging all user interactions, PowerShell logging, and other features that take note when a shell interface is used will provide you with more insight.
    
- `Anomalous network sessions`: Users tend to have a pattern they follow for network interaction. They visit the same websites, use the same applications, and often perform those actions multiple times a day like clockwork. Logging and parsing NetFlow data can be a great way to spot anomalous network traffic. Looking at things such as top talkers, or unique site visits, watching for a heartbeat on a nonstandard port (like 4444, the default port used by Meterpreter), and monitoring any remote login attempts or bulk GET / POST requests in short amounts of time can all be indicators of compromise or attempted exploitation. Using tools like network monitors, firewall logs, and SIEMS can help bring a bit of order to the chaos that is network traffic.
## Establish Network Visibility
Much like identifying and then using various shells & payloads, `detection` & `prevention` requires a detailed understanding of the systems and overall network environment you are trying to protect. It's always essential to have good documentation practices so individuals responsible for keeping the environment secure can have consistent visibility of the devices, data, and traffic flow in the environments they administer.
Keep in mind that if a payload is successfully executed, it will need to communicate over the network, so this is why network visibility is essential within the context of shells & payloads. Having a network security appliance capable of [deep packet inspection](https://en.wikipedia.org/wiki/Deep_packet_inspection) can often act as an anti-virus for the network.

#### Following the Traffic
![[Pasted image 20250927184357.png]]
This is an excellent example of basic access and command execution to gain persistence via the addition of a user to the host. Regardless of the name `hacker` being used, if command-line logging is in place paired with the NetFlow data, we can quickly tell that the user is performing potentially malicious actions and triage this event to determine if an incident has occurred or if this is just some admin playing around.

## Protecting End Devices
`End devices` are the devices that connect at the "end" of a network. This means they are either the source or destination of data transmission. Some examples of end devices would be:
- Workstations (employees computers)
- Servers (providing various services on the network)
- Printers
- Network Attached Storage (NAS)
- Cameras
- Smart TVs
- Smart Speakers

We should prioritize the protection of these kinds of devices, especially those that run an operating system with a `CLI` that can be remotely accessed.