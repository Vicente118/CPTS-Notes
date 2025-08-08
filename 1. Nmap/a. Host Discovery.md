#### Scan Network Range

```bash
sudo nmap 10.10.10.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```
#### Scan IP List

```bash
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut  -d" " -f5
```
#### Reason of IP for being up
```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --reason 
```
- `-PE to make sure ICMP packets are send`
- `--reason displays the reason for specific result`

```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping 
```
- `--disable-arp-ping to disable ARP pings`

