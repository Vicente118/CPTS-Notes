### Context

```
We were commissioned by the company `Inlanefreight Ltd` to test three different servers in their internal network. The company uses many different services, and the IT security department felt that a penetration test was necessary to gain insight into their overall security posture.

The first server is an internal DNS server that needs to be investigated. In particular, our client wants to know what information we can get out of these services and how this information could be used against its infrastructure. Our goal is to gather as much information as possible about the server and find ways to use that information against the company. However, our client has made it clear that it is forbidden to attack the services aggressively using exploits, as these services are in production.

Additionally, our teammates have found the following credentials "ceil:qwer1234", and they pointed out that some of the company's employees were talking about SSH keys on a forum.

The administrators have stored a `flag.txt` file on this server to track our progress and measure success. Fully enumerate the target and submit the contents of this file as proof.
```

### Question 

 Enumerate the server carefully and find the flag.txt file. Submit the contents of this file as the answer.


### Solution 

Creds: ceil:qwer1234
SSH Keys ?
Need to find flag.txt

```shell
> wget -m --no-passive ftp://ceil:qwer1234@10.129.69.8:2121
> cat .ssh/id_rsa
> chmod 600 id_rsa
> ssh ceil@10.129.69.8 -i id_rsa

ssh > cat flag.txt
HTB{7nrzise7hednrxihskjed7nzrgkweunj47zngrhdbkjhgdfbjkc7hgj}
```