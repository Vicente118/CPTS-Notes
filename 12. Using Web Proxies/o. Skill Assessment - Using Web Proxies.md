We are performing internal penetration testing for a local company. As you come across their internal web applications, you are presented with different situations where Burp/ZAP may be helpful. Read each of the scenarios in the questions below, and determine the features that would be the most useful for each case. Then, use it to help you in reaching the specified goal.


### Solution
1. The /lucky.php page has a button that appears to be disabled. Try to enable the button, and then click it to get the flag.
```
1. Go to Match and Rules settings and replace disabled by nothing. Then turn off intercept and click on the button until the flag appears.
HTB{d154bl3d_bu770n5_w0n7_570p_m3}
```

2.  The /admin.php page uses a cookie that has been encoded multiple times. Try to decode the cookie until you get a value with 31-characters. Submit the value as the answer.
```
The cookie is base64 encoded and ASCII HEX encoded.
The last character is missing so we will fuzz it to know what is hiding behind this hash.
> for i in $(cat /opt/lists/seclists/Fuzzing/alphanum-case.txt) ; do (echo -n "3dac93b8cd250aa8c1a36fffc79a17a$i\n"); done
```

3.  Once you decode the cookie, you will notice that it is only 31 characters long, which appears to be an md5 hash missing its last character. So, try to fuzz the last character of the decoded md5 cookie with all alpha-numeric characters, while encoding each request with the encoding methods you identified above. (You may use the "alphanum-case.txt" wordlist from Seclist for the payload)
```
Send request to intruder:
Replace cookie by $$
Load alphanum-case.txt
Add rule to add prefix (Our md5 uncomplete value)
Add rule to encode in base64
Add rule to encode in Hex

Launch attack.
HTB{burp_1n7rud3r_n1nj4!}
```

4. You are using the 'auxiliary/scanner/http/coldfusion_locale_traversal' tool within Metasploit, but it is not working properly for you. You decide to capture the request sent by Metasploit so you can manually verify it and repeat it. Once you capture the request, what is the 'XXXXX' directory being called in '/XXXXX/administrator/..'?
```
Just run the module with burp as proxy and we see the Directory:
/CFIDE/administrator/index.cfm
```