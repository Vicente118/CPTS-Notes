Burp's web fuzzer is called `Burp Intruder`, and can be used to fuzz pages, directories, sub-domains, parameters, parameters values, and many other things. Though it is much more advanced than most CLI-based web fuzzing tools, the free `Burp Community` version is throttled at a speed of 1 request per second, making it extremely slow compared to CLI-based web fuzzing tools, which can usually read up to 10k requests per second. This is why we would only use the free version of Burp Intruder for short queries.
## Target
 Once we do, we can go to the Proxy History, locate our request, then right-click on the request and select `Send to Intruder`, or use the shortcut [`CTRL+I`] to send it to `Intruder`.
 We can then go to `Intruder` by clicking on its tab or with the shortcut [`CTRL+SHIFT+I`], which takes us right to `Burp Intruder`:
 ![[Pasted image 20251116163218.png]]

## Positions
'`Positions`', is where we place the payload position pointer, which is the point where words from our wordlist will be placed and iterated over. We will be demonstrating how to fuzz web directories, which is similar to what's done by tools like `ffuf` or `gobuster`.'

To check whether a web directory exists, our fuzzing should be in '`GET /DIRECTORY/`', such that existing pages would return `200 OK`, otherwise we'd get `404 NOT FOUND`. So, we will need to select `DIRECTORY` as the payload position, by either wrapping it with `§` or by selecting the word `DIRECTORY` and clicking on the `Add §` button:
![[Pasted image 20251116163307.png]]
Note: Be sure to leave the extra two lines at the end of the request, otherwise we may get an error response from the server.

## Payloads
On the '`Payloads`' section on the right-hand side, we get to choose and customize our payloads/wordlists. This payload/wordlist is what would be iterated over, and each element/line of it would be placed and tested one by one in the Payload Position we chose earlier. There are four main things we need to configure:
- Payload Position & Payload Type
- Payload Configuration
- Payload Processing
- Payload Encoding

#### Payload Position & Payload Type
The first thing we must configure is the `Payload Position` and `Payload Type`. The payload set identifies the Payload number, depending on the attack type and number of Payloads we used in the Payload Position Pointers:
In this case, we only have one Payload Position, as we chose the '`Sniper`' Attack type with only one payload position. If we have chosen the '`Cluster Bomb`' attack type, for example, and added several payload positions, we would get more payload positions to choose from and choose different options for each. In our case, we'll select `1 - DIRECTORY` for the payload set.

Next, we need to select the `Payload Type`, which is the type of payloads/wordlists we will be using. Burp provides a variety of Payload Types, each of which acts in a certain way. For example:
- `Simple List`: The basic and most fundamental type. We provide a wordlist, and Intruder iterates over each line in it.
- `Runtime file`: Similar to `Simple List`, but loads line-by-line as the scan runs to avoid excessive memory usage by Burp.
- `Character Substitution`: Lets us specify a list of characters and their replacements, and Burp Intruder tries all potential permutations.

#### Payload Configuration
We will select `/opt/useful/seclists/Discovery/Web-Content/common.txt` as our wordlist. We can see that Burp Intruder loads all lines of our wordlist into the Payload Configuration table:
![[Pasted image 20251116163916.png]]
#### Payload Processing
Another option we can apply is `Payload Processing`, which allows us to determine fuzzing rules over the loaded wordlist. For example, if we wanted to add an extension after our payload item, or if we wanted to filter the wordlist based on specific criteria, we can do so with payload processing.

Let's try adding a rule that skips any lines that start with a `.` (as shown in the wordlist screenshot earlier). We can do that by clicking on the `Add` button and then selecting `Skip if matches regex`, which allows us to provide a regex pattern for items we want to skip. Then, we can provide a regex pattern that matches lines starting with `.`, which is: `^\..*$`:

#### Payload Encoding
The fourth and final option we can apply is `Payload Encoding`, enabling us to enable or disable Payload URL-encoding.
![Payload Encoding settings with URL-encode option for characters: ./^=<>&+?*:;'{}|^](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/110/burp_intruder_payload_encoding.png)

## Settings
Finally, we can customize our attack options from the `Settings` tab. There are many options we can customize (or leave at default) for our attack. For example, we can set the `Number of retries on network failure` and `Pause before retry` to 0.
 As we are fuzzing web directories, we are only interested in responses with HTTP code `200 OK`. So, we'll first enable it and then click `Clear` to clear the current list. After that, we can type `200 OK` to match any requests with this string and click `Add` to add the new rule. Finally, we'll also disable `Exclude HTTP Headers`, as what we are looking for is in the HTTP header:
 ![[Pasted image 20251116164107.png]]

## Attack
Now that everything is properly set up, we can click on the `Start Attack` button and wait for our attack to finish. Once again, in the free `Community Version`, these attacks would be very slow and take a considerable amount of time for longer wordlists.
