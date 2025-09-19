Once the DNS directs traffic to the correct server, the web server configuration becomes crucial in determining how the incoming requests are handled. Web servers like Apache, Nginx, or IIS are designed to host multiple websites or applications on a single server. They achieve this through virtual hosting, which allows them to differentiate between domains, subdomains, or even separate websites with distinct content.

## How Virtual Hosts Work: Understanding VHosts and Subdomains

At the core of `virtual hosting` is the ability of web servers to distinguish between multiple websites or applications sharing the same IP address.

The key difference between `VHosts` and `subdomains` is their relationship to the `Domain Name System (DNS)` and the web server's configuration.

- `Subdomains`: These are extensions of a main domain name (e.g., `blog.example.com` is a subdomain of `example.com`). `Subdomains` typically have their own `DNS records`, pointing to either the same IP address as the main domain or a different one. They can be used to organise different sections or services of a website.
- `Virtual Hosts` (`VHosts`): Virtual hosts are configurations within a web server that allow multiple websites or applications to be hosted on a single server. They can be associated with top-level domains (e.g., `example.com`) or subdomains (e.g., `dev.example.com`). Each virtual host can have its own separate configuration, enabling precise control over how requests are handled.

 If a virtual host does not have a DNS record, you can still access it by modifying the `hosts` file on your local machine. The `hosts` file allows you to map a domain name to an IP address manually, bypassing DNS resolution.


Virtual hosts can also be configured to use different domains, not just subdomains. For example:

```apacheconf
# Example of name-based virtual host configuration in Apache
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```

Here, `example1.com`, `example2.org`, and `another-example.net` are distinct domains hosted on the same server. The web server uses the `Host` header to serve the appropriate content based on the requested domain name.


### Server VHost Lookup\
The following illustrates the process of how a web server determines the correct content to serve based on the `Host` header:
![Sequence diagram showing interactions between Browser, WebServer, VirtualHostConfig, and DocumentRoot. Includes HTTP request, server response, and file access steps.](https://mermaid.ink/svg/pako:eNqNUsFuwjAM_ZUop00CPqAHDhubuCBNBW2XXrzUtNFap3McOoT496WUVUA3aTkltp_f84sP2rgcdaI9fgYkgwsLBUOdkYqnARZrbAMk6oFd65HHiTd8XyPvfku9WpYA1dJ5eXS0tcW4ZOFMqJEkdU4y6vNnqul8PvRO1HKzeVFpp9KLumvbdmapAsItoy1KmRlX3_fwAXTd4OkLakuoOjVqiZAj_7_PaJJEPVvK1QrElJYK1UcDg1h3HmOEmV4LSlEC0-CA6i24Zb406IRhizuM7BV6BVFCit4FNuh77GX9DeGfmEu-s_mD4b5x5PH2Y4aqhfVNBftufomsGemJrpFrsHncqkOHy7SUWGOmk3jNgT8yndEx1kEQt96T0YlwwIlmF4pSJ1uofHyFJgf52cchirkVx6t-aU-7e_wG--_4bQ)

1. `Browser Requests a Website`: When you enter a domain name (e.g., `www.inlanefreight.com`) into your browser, it initiates an HTTP request to the web server associated with that domain's IP address.
2. `Host Header Reveals the Domain`: The browser includes the domain name in the request's `Host` header, which acts as a label to inform the web server which website is being requested.
3. `Web Server Determines the Virtual Host`: The web server receives the request, examines the `Host` header, and consults its virtual host configuration to find a matching entry for the requested domain name.
4. `Serving the Right Content`: Upon identifying the correct virtual host configuration, the web server retrieves the corresponding files and resources associated with that website from its document root and sends them back to the browser as the HTTP response.


### Types of Virtual Hosting

There are three primary types of virtual hosting, each with its advantages and drawbacks:

1. `Name-Based Virtual Hosting`: This method relies solely on the `HTTP Host header` to distinguish between websites. It is the most common and flexible method, as it doesn't require multiple IP addresses. It’s cost-effective, easy to set up, and supports most modern web servers. However, it requires the web server to support name-based `virtual hosting` and can have limitations with certain protocols like `SSL/TLS`.
2. `IP-Based Virtual Hosting`: This type of hosting assigns a unique IP address to each website hosted on the server. The server determines which website to serve based on the IP address to which the request was sent. It doesn't rely on the `Host header`, can be used with any protocol, and offers better isolation between websites. Still, it requires multiple IP addresses, which can be expensive and less scalable.
3. `Port-Based Virtual Hosting`: Different websites are associated with different ports on the same IP address. For example, one website might be accessible on port 80, while another is on port 8080. `Port-based virtual hosting` can be used when IP addresses are limited, but it’s not as common or user-friendly as `name-based virtual hosting` and might require users to specify the port number in the URL.


## Virtual Host Discovery Tools

While manual analysis of `HTTP headers` and reverse `DNS lookups` can be effective, specialised `virtual host discovery tools` automate and streamline the process, making it more efficient and comprehensive. These tools employ various techniques to probe the target server and uncover potential `virtual hosts`.

Several tools are available to aid in the discovery of virtual hosts:

|Tool|Description|Features|
|---|---|---|
|[gobuster](https://github.com/OJ/gobuster)|A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery.|Fast, supports multiple HTTP methods, can use custom wordlists.|
|[Feroxbuster](https://github.com/epi052/feroxbuster)|Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility.|Supports recursion, wildcard discovery, and various filters.|
|[ffuf](https://github.com/ffuf/ffuf)|Another fast web fuzzer that can be used for virtual host discovery by fuzzing the `Host` header.|Customizable wordlist input and filtering options.|

### Gobuster

```shell
$ gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```

There are a couple of other arguments that are worth knowing:
- Consider using the `-t` flag to increase the number of threads for faster scanning.
- The `-k` flag can ignore SSL/TLS certificate errors.
- You can use the `-o` flag to save the output to a file for later analysis.


### Questions 

Find every Vhosts:
```shell
> gobuster vhost -u http://inlanefreight.htb:48555 -w `fzf-wordlists` --append-domain

Found: blog.inlanefreight.htb:48555 Status: 200 [Size: 98]
Found: admin.inlanefreight.htb:48555 Status: 200 [Size: 100]
Found: forum.inlanefreight.htb:48555 Status: 200 [Size: 100]
Found: support.inlanefreight.htb:48555 Status: 200 [Size: 104]
Found: vm5.inlanefreight.htb:48555 Status: 200 [Size: 96]
Found: browse.inlanefreight.htb:48555 Status: 200 [Size: 102]
Found: web17611.inlanefreight.htb:48555 Status: 200 [Size: 106]
```

