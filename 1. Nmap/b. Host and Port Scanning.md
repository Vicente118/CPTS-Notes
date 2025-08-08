#### States for a scanned port

| State            | Description                                                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| open             | The connection has been established. TCP, UDP or SCTP associations                                                              |
| closed           | Packet we received back contains an RST flag.                                                                                   |
| filtered         | Nmap cannot identify if the port is open or alive, no response was received or we got an error code from target.                |
| unfiltered       | Only for TCP-ACK scan, it means that the port is accessible but it cannot determine wheter it's open or closed                  |
| open\|filtered   | Indicate that a firewall or packet filter may protect the port                                                                  |
| closed\|filtered | Only for IP ID idle scans, indicates that it was impossible to determine if the scanned port is close or filtered by a firewall |
#### Discovering Top 10 TCP Ports
```bash
sudo nmap 10.129.2.28 --top-ports=10 
```

#### Trace Packets
```bash
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping

SENT (0.0429s) TCP 10.10.14.2:63090 > 10.129.2.28:21 S ttl=56 id=57322 iplen=44  seq=1699105818 win=1024 <mss 1460>
RCVD (0.0573s) TCP 10.129.2.28:21 > 10.10.14.2:63090 RA ttl=64 id=0 iplen=40  seq=0 win=0

```

#### Connect Scan
```bash
sudo nmap 10.129.2.28 -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT
```
- This scan is a makes a full TCP connection, not stealthy BUT can bypass firewalls in certains cases.

#### Filtered Ports
- Mostly caused by firewalls.

#### Discovering Open UDP Ports
```bash
sudo nmap 10.10.10.10 -F -sU
```
-  `-F for top 100 ports`

```bash
sudo nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 137 --reason

SENT (0.0445s) UDP 10.10.14.2:63825 > 10.129.2.28:100 ttl=57 id=29925 iplen=28
RCVD (0.1498s) ICMP [10.129.2.28 > 10.10.14.2 Port unreachable (type=3/code=3) ] IP [ttl=64 id=11903 iplen=56 ]
```
- `-n Disable DNS resolution`
- If the ICMP code is 3, the port is unreachable and we can conclude the port is closed

#### Version Scan
```bash
sudo nmap 10.129.2.28 -Pn -n --disable-arp-ping --packet-trace -p 445 --reason  -sV
```
