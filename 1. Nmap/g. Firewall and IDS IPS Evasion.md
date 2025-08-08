- These methods include the fragmentation of packets, the use of decoys, and others that we will discuss in this section.

#### Determine Firewalls and Their Rules

- If a packet is shown as filtered by a firewalls, it can be either `dropped` or `rejected`.
- The dropped packets are ignored and no response is returned from the host.
- Rejected packets are returned with an RST flag. These packets contain different types of ICMP error codes or contain nothing at all. Error are such as:
	- Net Unreachable
	- Net Prohibited
	- Host Unreachable
	- Host Prohibited
	- Port Unreachable
	- Proto Unreachable

- Nmap's TCP ACK scan `-sA` are much harder to filter for firewalls, IDS and IPS that regular SYN `-sS` or TCP full scan `-sT` because it only send a packet with ACK flag.

#### Detect IDS/IPS
- More difficult to detect.
- IDS Examine all connections between hosts. The hosts have to take the apporptiate action.
- IPS Takes measure configured by the administrator to prevent potential attacks.
- IPS is a complement to IDS.

#### Decoy
```shell
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```
- Nmap insert 5 different ip's in each packets header to disguise the origin of the packet sent.

```shell
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```

- `-e tun0`  Sends all requests through the specified interface.

#### DNS Proxying
```shell
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```