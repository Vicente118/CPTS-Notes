
Laudanum is a repository of ready-made files that can be used to inject onto a victim and receive back access via a reverse shell, run commands on the victim host right from the browser, and more. The repo includes injectable files for many different web application languages to include `asp, aspx, jsp, php,` and more.
You can get it [here](https://github.com/jbarcia/Web-Shells/tree/master/laudanum). Let's examine Laudanum and see how it works.

For specific files such as the shells, you must edit the file first to insert your `attacking` host IP address to ensure you can access the web shell or receive a callback in the instance that you use a reverse shell.

## Laudanum Demonstration
If you wish to follow along with this demonstration, you will need to add an entry into your `/etc/hosts` file on your attack VM or within Pwnbox for the host we are attacking. That entry should read: `<target ip> status.inlanefreight.local`.

#### Move a Copy for Modification
```shell
$ cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```

Add your IP address to the `allowedIps` variable on line `59`. Make any other changes you wish. It can be prudent to remove the ASCII art and comments from the file. These items in a payload are often signatured on and can alert the defenders/AV to what you are doing.

#### Modify the Shell for Use

![[Pasted image 20250927131454.png]]

We are taking advantage of the upload function at the bottom of the status page(`Green Arrow`) for this to work.

![[Pasted image 20250927131516.png]]

Once the upload is successful, you will need to navigate to your web shell to utilize its functions. The image below shows us how to do it. As seen from the last image, our shell was uploaded to the `\\files\` directory, and the name was kept the same. This won't always be the case. You may run into some implementations that randomize filenames on upload that do not have a public files directory or any number of other potential safeguards. For now, we are lucky that's not the case. With this particular web application, our file went to `status.inlanefreight.local\\files\demo.aspx` and will require us to browse for the upload by using that \ in the path instead of the / like normal. Once you do this, your browser will clean it up in your URL window to appear as `status.inlanefreight.local//files/demo.aspx`.

#### Navigate to Our Shell
![[Pasted image 20250927131600.png]]

We can now utilize the Laudanum shell we uploaded to issue commands to the host. We can see in the example that the `systeminfo` command was run.

![[Pasted image 20250927131606.png]]
