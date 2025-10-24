## Scenario

A team member started a Penetration Test against the Inlanefreight environment but was moved to another project at the last minute. Luckily for us, they left a `web shell` in place for us to get back into the network so we can pick up where they left off. We need to leverage the web shell to continue enumerating the hosts, identifying common services, and using those services/protocols to pivot into the internal networks of Inlanefreight. Our detailed objectives are `below`:
## Objectives
- Start from external (`Pwnbox or your own VM`) and access the first system via the web shell left in place.
- Use the web shell access to enumerate and pivot to an internal host.
- Continue enumeration and pivoting until you reach the `Inlanefreight Domain Controller` and capture the associated `flag`.
- Use any `data`, `credentials`, `scripts`, or other information within the environment to enable your pivoting attempts.
- Grab `any/all` flags that can be found.

**Note:**
Keep in mind the tools and tactics you practiced throughout this module. Each one can provide a different route into the next pivot point. You may find a hop to be straightforward from one set of hosts, but that same tactic may not work to get you to the next. While completing this skills assessment, we encourage you to take proper notes, draw out a map of what you know of already, and plan out your next hop. Trying to do it on the fly will prove `difficult` without having a visual to reference.

## Questions and Solutions

1.  Once on the webserver, enumerate the host for credentials that can be used to start a pivot or tunnel to another host in the network. In what user's directory can you find the credentials? Submit the name of the user as the answer.
```shell
We can find a /home/webadmin direcotry with credentials

Answer: webadmin
```

2. Submit the credentials found in the user's home directory. (Format: user:password)
```shell
mlefay:Plain Human work!

(Found id_rsa as well)
```

3. Enumerate the internal network and discover another active host. Submit the IP address of that host as the answer.
```shell
Get a reverse shell from Pwnyshell to host for better stability.
Then perform a ping sweep:
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
.$i | grep "bytes from" &) ;done 172.16.5.
64 bytes from 172.16.5.15: icmp_seq=1 ttl=64 time=0.019 ms
64 bytes from 172.16.5.35: icmp_seq=1 ttl=128 time=0.421 ms

172.16.5.35
```

4.  Use the information you gathered to pivot to the discovered host. Submit the contents of C:\Flag.txt as the answer
```shell
Used Chisel to pivot and get into internal network via xfreerdp.
Then dump lsass.exe since we have privilege for.
Finally tranfer to our attacker machine de lsass.dmp.
S1ngl3-Piv07-3@sy-Day

Perform a ping sweep with new PIC in the restricted network (Third)
We find :
172.16.6.25
172.16.6.45
```
5.  In previous pentests against Inlanefreight, we have seen that they have a bad habit of utilizing accounts with services in a way that exposes the users credentials and the network as a whole. What user is vulnerable?
```shell
vfrank (See lsass.dmp)
Make port forwarding with netsh
and connect to vfrank
> proxychains xfreerdp /v:172.16.5.35:8080 /u:vfrank /pth:'2e16a00be74fa0bf862b4256d0347e83' /drive:share,/workspace/CPTS/tmp 
```

6. Find flag on DC C:\Flag.txt
```txt
Check Shares and find the Flag
```