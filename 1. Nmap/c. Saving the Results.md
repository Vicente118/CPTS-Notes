#### Different Formats
1. `-oN`: Normal output .nmap
2. `-oG`: Grepable output .gnmap
3. `-oX`: XML output .xml
4. `-oA`: All of them will be created

- With the XML output we can transform the file to a html file in order to have a nice overview of our scan in the browser.
```bash
xsltproc target.xml -o target.html
```
