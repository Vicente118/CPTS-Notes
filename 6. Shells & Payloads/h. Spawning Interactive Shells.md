There may be times that we land on a system with a limited shell, and Python is not installed. In these cases, it's good to know that we could use several different methods to spawn an interactive shell. Let's examine some of them.

## /bin/sh -i
This command will execute the shell interpreter specified in the path in interactive mode (`-i`).
#### Interactive
```shell
/bin/sh -i
```

## Perl

```shell
perl —e 'exec "/bin/sh";'
```

```shell
perl: exec "/bin/sh";
```
The command directly above should be run from a script.
## Ruby

```shell
ruby: exec "/bin/sh"
```
The command directly above should be run from a script.


## Lua

```shell
lua: os.execute('/bin/sh')
```
The command directly above should be run from a script.

## AWK

```shell
awk 'BEGIN {system("/bin/sh")}'
```

## Find

```shell
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

## Using Exec To Launch A Shell

```shell
find . -exec /bin/sh \; -quit
```

## VIM
```shell
vim -c ':!/bin/sh'
```

#### Vim Escape

```shell
vim
:set shell=/bin/sh
:shell
```

## Execution Permissions Considerations

We can also attempt to run this command to check what `sudo` permissions the account we landed on has:
```shell
sudo -l
Matching Defaults entries for apache on ILF-WebSrv:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User apache may run the following commands on ILF-WebSrv:
    (ALL : ALL) NOPASSWD: ALL
```

The sudo -l command above will need a stable interactive shell to run. If you are not in a full shell or sitting in an unstable shell, you may not get any return from it. Not only will considering permissions allow us to see what commands we can execute, but it may also start to give us an idea of potential vectors that will allow us to escalate privileges.
