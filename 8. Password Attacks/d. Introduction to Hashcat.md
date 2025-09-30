[Hashcat](https://hashcat.net/) is a well-known password cracking tool for Linux, Windows, and macOS. From 2009 until 2015 it was proprietary software, but has since been released as open-source. Featuring fantastic GPU support, it can be used to crack a large variety of hashes. Similar to JtR, hashcat supports multiple attack (cracking) modes which can be used to efficiently attack password hashes.

The general syntax used to run hashcat is as follows:
```shell-session
hashcat -a 0 -m 0 <hashes> [wordlist, rule, mask, ...]
```

`-a` is used to specify the ATTACK MODE
`-m` is used to specify the HASH TYPE
`<hashes>` is a either a hash string or a file containing one or more password hashes of the same type.
`[wordlist, rule, mask, ...]` is a placeholder for additional arguments that depend on the attack mode.

## Hash types

```shell
hashcat --help | less (Then look for `Hash modes`)
```

The hashcat website hosts a comprehensive list of [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) which can assist in manually identifying an unknown hash type and determining the corresponding Hashcat hash mode identifier.
Alternatively, [hashID](https://github.com/psypanda/hashID) can be used to quickly identify the hashcat hash type by specifying the `-m` argument.

```shell
hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'

Analyzing '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'
[+] MD5 Crypt [Hashcat Mode: 500]
[+] Cisco-IOS(MD5) [Hashcat Mode: 500]
[+] FreeBSD MD5 [Hashcat Mode: 500]
```

## Attack modes
Hashcat has many different attack mode, including `dictionary`, `mask`, `combinator`, and `association`. In this section we will go over the first two, as they are likely the most common ones that you will need to use.
#### Dictionary attack
[Dictionary attack](https://hashcat.net/wiki/doku.php?id=dictionary_attack) (`-a 0`) is, as the name suggests, a dictionary attack. The user provides password hashes and a wordlist as input, and Hashcat tests each word in the list as a potential password until the correct one is found or the list is exhausted.
As an example, imagine we extracted the following password hash from an SQL database: `e3e3ec5831ad5e7288241960e5d4fdb8`. First, we could identify this as an MD5 hash, which has a hash ID of `0`. To attempt to crack this hash using the `rockyou.txt` wordlist, the following command would be used:

```shell
hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt
```

A wordlist alone is often not enough to crack a password hash. As was the case with JtR, `rules` can be used to perform specific modifications to passwords to generate even more guesses. The rule files that come with hashcat are typically found under `/usr/share/hashcat/rules`:
```shell
> ls -l /usr/share/hashcat/rules

best64.rule      Incisive-leetspeak.rule      T0XlC_3_rule.rule
...
...
```
As another example, imagine an additional md5 hash was leaked from the SQL database: `1b0556a75770563578569ae21392630c`. We weren't able to crack it using `rockyou.txt` alone, so in a subsequent attempt, we might apply some common rule-based transformations. One ruleset we could try is `best64.rule`, which contains 64 standard password modifications—such as appending numbers or substituting characters with their "leet" equivalents. To perform this kind of attack, we would append the `-r <ruleset>` option to the command, as shown below:

```shell
hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

#### Mask attack
[Mask attack](https://hashcat.net/wiki/doku.php?id=mask_attack) (`-a 3`) is a type of brute-force attack in which the keyspace is explicitly defined by the user. For example, if we know that a password is eight characters long, rather than attempting every possible combination, we might define a mask that tests combinations of six letters followed by two numbers.

A mask is defined by combining a sequence of symbols, each representing a built-in or custom character set. Hashcat includes several built-in character sets:

| Symbol | Charset                             |
| ------ | ----------------------------------- |
| ?l     | abcdefghijklmnopqrstuvwxyz          |
| ?u     | ABCDEFGHIJKLMNOPQRSTUVWXYZ          |
| ?d     | 0123456789                          |
| ?h     | 0123456789abcdef                    |
| ?H     | 0123456789ABCDEF                    |
| ?s     | «space»!"#$%&'()*+,-./:;<=>?@[]^_`{ |
| ?a     | ?l?u?d?s                            |
| ?b     | 0x00 - 0xff                         |
Custom charsets can be defined with the `-1`, `-2`, `-3`, and `-4` arguments, then referred to with `?1`, `?2`, `?3`, and `?4`.
Let's say that we specifically want to try passwords which start with an uppercase letter, continue with four lowercase letters, a digit, and then a symbol. The resulting hashcat mask would be `?u?l?l?l?l?d?s`.

```shell
hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'
```

### Questions

1. Use a dictionary attack to crack the first password hash. (Hash: e3e3ec5831ad5e7288241960e5d4fdb8)
2. Use a dictionary attack with rules to crack the second password hash. (Hash: 1b0556a75770563578569ae21392630c)
3. Use a mask attack to crack the third password hash. (Hash: 1e293d6912d074c0fd15844d803400dd)


```shell
1:
Hash : e3e3ec5831ad5e7288241960e5d4fdb8
Type : MD5 Thanks to online hashid

> hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt

e3e3ec5831ad5e7288241960e5d4fdb8:crazy!


2:
Hash : 1b0556a75770563578569ae21392630c
Type : MD5

> hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

1b0556a75770563578569ae21392630c:


3:
Hash : 1e293d6912d074c0fd15844d803400dd
Type : MD5

> hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'

1e293d6912d074c0fd15844d803400dd:Mouse5!
```