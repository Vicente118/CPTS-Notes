## Proxy History
To start, we can view the HTTP requests history in `Burp` at (`Proxy>HTTP History`):
![[Pasted image 20251116155603.png]]

In `ZAP` HUD, we can find it in the bottom History pane or ZAP's main UI at the bottom `History` tab as well:
![[Pasted image 20251116155611.png]]

If we click on any request in the history in either tool, its details will be shown:

`Burp`: ![Request and response details: POST to /ping with headers and IP, response 200 OK with ping statistics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/110/burp_history_details.png)

`ZAP`: ![Request and response details: POST to /ping with headers and IP, response 200 OK with ping statistics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/110/zap_history_details.png)

## Repeating Requests
#### Burp
Once we locate the request we want to repeat, we can click [`CTRL+R`] in Burp to send it to the `Repeater` tab, and then we can either navigate to the `Repeater` tab or click [`CTRL+SHIFT+R`] to go to it directly. Once in `Repeater`, we can click on `Send` to send the request:
![[Pasted image 20251116155809.png]]
Tip: We can also right-click on the request and select `Change Request Method` to change the HTTP method between POST/GET without having to rewrite the entire request.


#### ZAP
In ZAP, once we locate our request, we can right-click on it and select `Open/Resend with Request Editor`, which would open the request editor window, and allow us to resend the request with the `Send` button to send our request:
![[Pasted image 20251116155851.png]]
We can also see the `Method` drop-down menu, allowing us to quickly switch the request method to any other HTTP method.
