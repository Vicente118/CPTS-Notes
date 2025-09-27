## ASPX and a Quick Learning Tip
It is good to supplement reading with watching demonstrations and performing hands-on as we have been doing thus far. Video walkthroughs can be an amazing way to learn concepts, plus they can be consumed casually (eating lunch, laying in bed, sitting on the couch, etc.). One great resource to use in learning is `IPPSEC's` blog site [ippsec.rocks](https://ippsec.rocks/?#).

## ASPX Explained
`Active Server Page Extended` (`ASPX`) is a file type/extension written for [Microsoft's ASP.NET Framework](https://docs.microsoft.com/en-us/aspnet/overview). On a web server running the ASP.NET framework, web form pages can be generated for users to input data. On the server side, the information will be converted into HTML. We can take advantage of this by using an ASPX-based web shell to control the underlying Windows operating system. Let's witness this first-hand by utilizing the Antak Webshell.

## Antak Webshell
Antak is a web shell built in ASP.Net included within the [Nishang project](https://github.com/samratashok/nishang). Nishang is an Offensive PowerShell toolset that can provide options for any portion of your pentest. Since we are focused on web applications for the moment, let's keep our eyes on `Antak`. Antak utilizes PowerShell to interact with the host, making it great for acquiring a web shell on a Windows server.

## Working with Antak

The Antank file scan be found in /opt/nishang/Antak-WebShell

## Antak Demonstration
#### Modify the Shell for Use
![[Pasted image 20250927143643.png]]

Upload the file like on the Laudanum section.
![[Pasted image 20250927143957.png]]

![[Pasted image 20250927144006.png]]

Now that we have access, we can utilize PowerShell commands to navigate and take actions against the host. We can issue basic commands from the Antak shell window, upload and download files, encode and execute scripts, and much more (green arrow below). This is an excellent way to utilize a Webshell to deliver us a callback to our command and control platform.

### Questions

Reproduce above demonstration and enter `whoami` command.
User: iis apppool\status