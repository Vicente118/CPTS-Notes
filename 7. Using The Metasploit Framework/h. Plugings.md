Plugins are readily available software that has already been released by third parties and have given approval to the creators of Metasploit to integrate their software inside the framework.

## Using Plugins
To start using a plugin, we will need to ensure it is installed in the correct directory on our machine. Navigating to `/opt/metasploit/plugins`.

#### MSF - Load Nessus
```shell
msf6 > load nessus
```
```shell-session
msf6 > nessus_help
```

## Installing new Plugins
To install new custom plugins not included in new updates of the distro, we can take the .rb file provided on the maker's page and place it in the folder at `/usr/share/metasploit-framework/plugins` with the proper permissions.

#### Downloading MSF Plugins
```shell-session
git clone https://github.com/darkoperator/Metasploit-Plugins
```
Here we can take the plugin `pentest.rb` as an example and copy it to `/usr/share/metasploit-framework/plugins`.

#### MSF - Copying Plugin to MSF
```shell-session
sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
```
Afterward, launch `msfconsole` and check the plugin's installation by running the `load` command. After the plugin has been loaded, the `help menu` at the `msfconsole` is automatically extended by additional functions.

#### MSF - Load Plugin
```shell-session
msf6 > load pentest
```

Many people write many different plugins for the Metasploit framework. They all have a specific purpose and can be an excellent help to save time after familiarizing ourselves with them. Check out the list of popular plugins below:
![[Pasted image 20250928152921.png]]


## Mixins
Mixins are classes that act as methods for use by other classes without having to be the parent class of those other classes. Thus, it would be deemed inappropriate to call it inheritance but rather inclusion. They are mainly used when we:
1. Want to provide a lot of optional features for a class.
2. Want to use one particular feature for a multitude of classes.

