Already now how to setup proxy

## Installing CA Certificate
We can install Burp's certificate once we select Burp as our proxy in `Foxy Proxy`, by browsing to `http://burp`, and downloading the certificate from there by clicking on `CA Certificate`:
![[Pasted image 20251116151016.png]]

To get ZAP's certificate, we can go to (`Tools>Options>Network>Server Certificates`), then click on `Save`:
![[Pasted image 20251116151023.png]]

Once we have our certificates, we can install them within Firefox by browsing to [about:preferences#privacy](about:preferences#privacy), scrolling to the bottom, and clicking `View Certificates`:
![[Pasted image 20251116151038.png]]
After that, we can select the `Authorities` tab, and then click on `import`, and select the downloaded CA certificate:
![[Pasted image 20251116151044.png]]
Finally, we must select `Trust this CA to identify websites` and `Trust this CA to identify email users`, and then click OK:
![[Pasted image 20251116151049.png]]
