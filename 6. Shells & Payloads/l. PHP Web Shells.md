Hypertext Preprocessor or [PHP](https://www.php.net/) is an open-source general-purpose scripting language typically used as part of a web stack that powers a website. At the time of this writing (October 2021), PHP is the most popular `server-side programming language`. According to a [recent survey](https://w3techs.com/technologies/details/pl-php) conducted by W3Techs, "PHP is used by `78.6%` of all websites whose server-side programming language we know".

#### PHP Login Page
![[Pasted image 20250927144234.png]]Recall the rConfig server from earlier in this module? It uses PHP. We can see a `login.php` file. So when we select the login button after filling out the Username and Password field, that information is processed server-side using PHP. Knowing that a web server is using PHP gives us pentesters a clue that we may gain a PHP-based web shell on this system.\

## Hands-on With a PHP-Based Web Shell.
 In this case, we will take advantage of the vulnerability in rConfig 3.9.6 to manually upload a PHP web shell and interact with the underlying Linux host. In addition to all the functionality mentioned earlier, rConfig allows admins to add network devices and categorize them by vendor. Go ahead and log in to rConfig with the default credentials (admin:admin), then navigate to `Devices` > `Vendors` and click `Add Vendor`.
#### Vendors Tab
![[Pasted image 20250927144327.png]]

We will be using [WhiteWinterWolf's PHP Web Shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell). We can download this or copy and paste the source code into a `.php` file.
 Our goal is to upload the PHP web shell via the Vendor Logo `browse` button. Attempting to do this initially will fail since rConfig is checking for the file type. It will only allow uploading image file types (.png,.jpg,.gif, etc.). However, we can bypass this utilizing `Burp Suite`.
Our goal is to change the `content-type` to bypass the file type restriction in uploading files to be "presented" as the vendor logo so we can navigate to that file and have our web shell.

## Bypassing the File Type Restriction
Click the browse button, navigate to wherever our .php file is stored on our attack box, and select open and `Save` (we may need to accept the PortSwigger Certificate). It will seem as if the web page is hanging, but that's just because we need to tell Burp to forward the HTTP requests. Forward requests until you see the POST request containing our file upload. It will look like this:
![[Pasted image 20250927144910.png]]
As mentioned in an earlier section, you will notice that some payloads have comments from the author that explain usage, provide kudos and links to personal blogs. This can give us away, so it's not always best to leave the comments in place. We will change Content-type from `application/x-php` to `image/gif`.
This will essentially "trick" the server and allow us to upload the .php file, bypassing the file type restriction. Once we do this, we can select `Forward` twice, and the file will be submitted. We can turn the Burp interceptor off now and go back to the browser to see the results.

![[Pasted image 20250927144952.png]]

The message: `Added new vendor NetVen to Database` lets us know our file upload was successful.
We can also see the NetVen vendor entry with the logo showcasing a ripped piece of paper. This means rConfig did not recognize the file type as an image, so it defaulted to that image
We can now attempt to use our web shell. Using the browser, navigate to this directory on the rConfig server:
/images/vendor/connect.php
#### Webshell Success
![[Pasted image 20250927145109.png]]

## Considerations when Dealing with Web Shells

When utilizing web shells, consider the below potential issues that may arise during your penetration testing process:
- Web applications sometimes automatically delete files after a pre-defined period
- Limited interactivity with the operating system in terms of navigating the file system, downloading and uploading files, chaining commands together may not work (ex. `whoami && hostname`), slowing progress, especially when performing enumeration -Potential instability through a non-interactive web shell
- Greater chance of leaving behind proof that we were successful in our attack

Depending on the engagement type (i.e., a black box evasive assessment), we may need to attempt to go undetected and `cover our tracks`. We are often helping our clients test their capabilities to detect a live threat, so we should emulate as much as possible the methods a malicious attacker may attempt, including attempting to operate stealthily.


### Questions

According to rConfig CVE:
Add vendor and select web shell as image. Then intercept the upload with burp modify content type with `image/gif` and forward the request. Follow redirection if needed.
Then access this url: https://10.129.85.121/images/vendor/web.php

Gif name: ajax-loader.gif