We may want to apply certain modifications to all outgoing HTTP requests or all incoming HTTP responses in certain situations. In these cases, we can utilize automatic modifications based on rules we set, so the web proxy tools will automatically apply them.

## Automatic Request Modification
Let us start with an example of automatic request modification. We can choose to match any text within our requests, either in the request header or request body, and then replace it with different text. For the sake of demonstration, let's replace our `User-Agent` with `HackTheBox Agent 1.0`, which may be handy in cases where we may be dealing with filters that block certain User-Agents.

#### Burp Match and Replace
We can go to (`Proxy>Proxy settings>HTTP match and replace rules`) and click on `Add` in Burp. As the screenshot below shows, we will set the following options:![[Pasted image 20251116154746.png]]

|   |   |
|---|---|
|`Type`: `Request header`|Since the change we want to make will be in the request header and not in its body.|
|`Match`: `^User-Agent.*$`|The regex pattern that matches the entire line with `User-Agent` in it.|
|`Replace`: `User-Agent: HackTheBox Agent 1.0`|This is the value that will replace the line we matched above.|
|`Regex match`: True|We don't know the exact User-Agent string we want to replace, so we'll use regex to match any value that matches the pattern we specified above.|

---
#### ZAP Replacer
ZAP has a similar feature called `Replacer`, which we can access by pressing [`CTRL+R`] or clicking on `Replacer` in ZAP's options menu. It is fairly similar to what we did above, so we can click on `Add` and add the same options we used earlier:
![[Pasted image 20251116155050.png]]
- `Description`: `HTB User-Agent`.
- `Match Type`: `Request Header (will add if not present)`.
- `Match String`: `User-Agent`. We can select the header we want from the drop-down menu, and ZAP will replace its value.
- `Replacement String`: `HackTheBox Agent 1.0`.
- `Enable`: True.

ZAP also provides the option to set the `Initiators`, which we can access by clicking on the other tab in the windows shown above. Initiators enable us to select where our `Replacer` option will be applied. We will keep the default option of `Apply to all HTTP(S) messages` to apply everywhere.
We can now enable request interception by pressing [`CTRL+B`], then can visit any page in the pre-configured ZAP browser

## Automatic Response Modification
Let us go back to (`Proxy>Options>Match and Replace`) in Burp to add another rule. This time we will use the type of `Response body` since the change we want to make exists in the response's body and not in its headers. In this case, we do not have to use regex as we know the exact string we want to replace, though it is possible to use regex to do the same thing if we prefer.
![[Pasted image 20251116155232.png]]
- `Type`: `Response body`.
- `Match`: `type="number"`.
- `Replace`: `type="text"`.
- `Regex match`: False.
