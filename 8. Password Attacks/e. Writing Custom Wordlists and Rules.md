According to statistics provided by [WP Engine](https://wpengine.com/resources/passwords-unmasked-infographic/), most passwords are no longer than `ten` characters. One approach is to select familiar terms that are at least five characters long—such as pet names, hobbies, personal preferences, or other common interests. For instance, if a user selects a single word (e.g., the current month), appends the current year, and adds a special character at the end, the result may satisfy a typical ten-character password requirement.

Let's look at a simple example using a password list with only one entry.
```shell
$ cat password.list

password
```

We can use Hashcat to combine lists of potential names and labels with specific mutation rules to create custom wordlists. Hashcat uses a specific syntax to define characters, words, and their transformations. The complete syntax is documented in the official [Hashcat rule-based attack documentation](https://hashcat.net/wiki/doku.php?id=rule_based_attack), but the examples below are sufficient to understand how Hashcat mutates input words.

| **Function** | **Description**                                  |
| ------------ | ------------------------------------------------ |
| `:`          | Do nothing                                       |
| `l`          | Lowercase all letters                            |
| `u`          | Uppercase all letters                            |
| `c`          | Capitalize the first letter and lowercase others |
| `sXY`        | Replace all instances of X with Y                |
| `$!`         | Add the exclamation character at the end         |
Each rule is written on a new line and determines how a given word should be transformed. If we write the functions shown above into a file, it may look like this:
```shell
> cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

We can use the following command to apply the rules in `custom.rule` to each word in `password.list` and store the mutated results in `mut_password.list`.
```shell
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

In this case, the single input word will produce fifteen mutated variants.
```shell
> cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```

Hashcat and JtR both come with pre-built rule lists that can be used for password generation and cracking. One of the most effective and widely used rulesets is `best64.rule`, which applies common transformations that frequently result in successful password guesses.

## Generating wordlists using CeWL
We can use a tool called [CeWL](https://github.com/digininja/CeWL) to scan potential words from a company's website and save them in a separate list. We can then combine this list with the desired rules to create a customized password list—one that has a higher probability of containing the correct password for an employee. We specify some parameters, like the depth to spider (`-d`), the minimum length of the word (`-m`), the storage of the found words in lowercase (`--lowercase`), as well as the file where we want to store the results (`-w`).

```shell
> cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```

## Exercise
For this sections exercise, imagine that we compromised the password hash of a `work email` belonging to `Mark White`. After performing a bit of OSINT, we have gathered the following information about Mark:
- He was born on `August 5, 1998`
- He works at `Nexura, Ltd.`
    - The company's password policy requires passwords to be at least 12 characters long, to contain at least one uppercase letter, at least one lowercase letter, at least one symbol and at least one number
- He lives in `San Francisco, CA, USA`
- He has a pet cat named `Bella`
- He has a wife named `Maria`
- He has a son named `Alex`
- He is a big fan of `baseball`

The password hash is: `97268a8ae45ac7d15c3cea4ce6ea550b`. Use the techniques covered in this section to generate a custom wordlist and ruleset targeting Mark specifically, and crack the password.

What is Mark's password?

```shell
First let's create a python webserver that host a file with all the important informations.
```

```html
> cat password.html
<!DOCTYPE html>
<html>
<body>
<ul>
	<li>Mark White </li>
	<li>Born: August 5, 1998</li>
	<li>Works at Nexura, Ltd</li>
	<li>Lives in San Francisco , CA, USA</li>
	<li>Pet: cat named Bella</li>
	<li>Wife: Maria</li>
	<li>Son: Alex</li>
	<li>Fan of baseball</li>
</ul>
</body>
</html>
```

```shell
> cewl --depth 1 --with-numbers --write cewl.txt "http://localhost:8000/password.html" --verbose
> cat cewl.txt
Mark
White
Born
August
1998
Works
Nexura
Ltd
Lives
San
Francisco
USA
Pet
cat
named
Bella
Wife
Maria
Son
Alex
Fan
baseball
```

```shell
Let's combine each word two by two to get a larger wordlist (12 char min)

> hashcat -a 1 cewl.txt cewl.txt --stdout > cewl_combinations.txt

-a 1 is the combination mode

Let's now take the 12 length minimum passwords:
> awk 'length($0) >= 12' cewl_combinations.txt > combinations_12.txt

Let's try now to apply a custom rule to our wordlist.

cat << 'EOF' > custom.rule  
:  
c  
so0  
c so0  
sa@  
c sa@  
c sa@ so0  
$!  
$! c  
$! so0  
$! sa@  
$! c so0  
$! c sa@  
$! so0 sa@  
$! c so0 sa@  
EOF



Now we can apply the rule on the wordlist.
> hashcat --force combinations_12.txt -r custom.rule --stdout | sort -u > final.list

97268a8ae45ac7d15c3cea4ce6ea550b:Baseball1998!
```