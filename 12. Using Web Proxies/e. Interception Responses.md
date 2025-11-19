In some instances, we may need to intercept the HTTP responses from the server before they reach the browser. This can be useful when we want to change how a specific web page looks, like enabling certain disabled fields or showing certain hidden fields, which may help us in our penetration testing activities.

## Burp
In Burp, we can enable response interception by going to (`Proxy>Proxy settings`) and enabling `Intercept Response` under `Response interception rules`:
![[Pasted image 20251116152233.png]]

Intercept request [CTRL+SHIFT+R ] (Full refresh) and right click to enable intercept response. 
Then forward request, response will be intercepted and we can modify html/javascript for our need then forward response to our browser.
## ZAP
Let's try to see how we can do the same with ZAP. As we saw in the previous section, when our requests are intercepted by ZAP, we can click on `Step`, and it will send the request and automatically intercept the response:
![[Pasted image 20251116153505.png]]
Once we make the same changes we previously did and click on `Continue`
However, ZAP HUD also has another powerful feature that can help us in cases like this. While in many instances we may need to intercept the response to make custom changes, if all we wanted was to enable disabled input fields or show hidden input fields, then we can click on the third button on the left (the light bulb icon), and it will enable/show these fields without us having to intercept the response or refresh the page.
For example, the below web application has the `IP` input field disabled:
![[Pasted image 20251116153625.png]]
In these cases, we can click on the `Show/Enable` button, and it will enable the button for us, and we can interact with it to add our input:
![[Pasted image 20251116153646.png]]

We can similarly use this feature to show all hidden fields or buttons. `Burp` also has a similar feature, which we can enable under `Proxy>Proxy settings>Response modification rules`, then select one of the options, like `Unhide hidden form fields`.

Another similar feature is the `Comments` button, which will indicate the positions where there are HTML comments that are usually only visible in the source code. We can click on the `+` button on the left pane and select `Comments` to add the `Comments` button, and once we click on it, the `Comments` indicators should be shown. For example, the below screenshot shows an indicator for a position that has a comment, and hovering over it with our cursor shows the comment's content:
![[Pasted image 20251116153800.png]]