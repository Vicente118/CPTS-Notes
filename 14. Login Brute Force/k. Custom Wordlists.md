## Username Anarchy
Even when dealing with a seemingly simple name like "Jane Smith," manual username generation can quickly become a convoluted endeavor. While the obvious combinations like `jane`, `smith`, `janesmith`, `j.smith`, or `jane.s` may seem adequate, they barely scratch the surface of the potential username landscape.

Human creativity knows no bounds, and usernames often become a canvas for personal expression. Jane could seamlessly weave in her middle name, birth year, or a cherished hobby, leading to variations like `janemarie`, `smithj87`, or `jane_the_gardener`.

The allure of `leetspeak`, where letters are replaced with numbers or symbols, could manifest in usernames like `j4n3`, `5m1th`, or `j@n3_5m1th`. Her passion for a particular book, movie, or band might inspire usernames like `winteriscoming`, `potterheadjane`, or `smith_beatles_fan`.

This is where `Username Anarchy` shines. It accounts for initials, common substitutions, and more, casting a wider net in your quest to uncover the target's username:

```shell
./username-anarchy -l
```
Next, execute it with the target's first and last names. This will generate possible username combinations.
```shell
./username-anarchy Jane Smith > jane_smith_usernames.txt
```
Upon inspecting `jane_smith_usernames.txt`, you'll encounter a diverse array of usernames, encompassing:
- Basic combinations: `janesmith`, `smithjane`, `jane.smith`, `j.smith`, etc.
- Initials: `js`, `j.s.`, `s.j.`, etc.
- etc
This comprehensive list, tailored to the target's name, is valuable in a brute-force attack.

---
## CUPP
`CUPP` (Common User Passwords Profiler) is a tool designed to create highly personalized password wordlists that leverage the gathered intelligence about your target.

The efficacy of CUPP hinges on the quality and depth of the information you feed it. It's akin to a detective piecing together a suspect's profile - the more clues you have, the clearer the picture becomes. So, where can one gather this valuable intelligence for a target like Jane Smith?
- `Social Media`: A goldmine of personal details: birthdays, pet names, favorite quotes, travel destinations, significant others, and more. Platforms like Facebook, Twitter, Instagram, and LinkedIn can reveal much information.
- `Company Websites`: Jane's current or past employers' websites might list her name, position, and even her professional bio, offering insights into her work life.
- `Public Records`: Depending on jurisdiction and privacy laws, public records might divulge details about Jane's address, family members, property ownership, or even past legal entanglements.
- `News Articles and Blogs`: Has Jane been featured in any news articles or blog posts? These could shed light on her interests, achievements, or affiliations.

OSINT will be a goldmine of information for CUPP.

|Field|Details|
|---|---|
|Name|Jane Smith|
|Nickname|Janey|
|Birthdate|December 11, 1990|
|Relationship Status|In a relationship with Jim|
|Partner's Name|Jim (Nickname: Jimbo)|
|Partner's Birthdate|December 12, 1990|
|Pet|Spot|
|Company|AHI|
|Interests|Hackers, Pizza, Golf, Horses|
|Favorite Colors|Blue|

Invoke CUPP in interactive mode, CUPP will guide you through a series of questions about your target, enter the following as prompted:

```shell
> cupp -i

> First Name: Jane
> Surname: Smith
> Nickname: Janey
> Birthdate (DDMMYYYY): 11121990


> Partners) name: Jim
> Partners) nickname: Jimbo
> Partners) birthdate (DDMMYYYY): 12121990


> Child's name:
> Child's nickname:
> Child's birthdate (DDMMYYYY):


> Pet's name: Spot
> Company name: AHI
```

We now have a generated username.txt list and jane.txt password list, but there is one more thing we need to deal with. CUPP has generated many possible passwords for us, but Jane's company, AHI, has a rather odd password policy.
- Minimum Length: 6 characters
- Must Include:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least two special characters (from the set `!@#$%^&*`)

```shell
grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```

```shell
hydra -L usernames.txt -P jane-filtered.txt IP -s PORT -f http-post-form "/:username=^USER^&password=^PASS^:Invalid credentials"
```
