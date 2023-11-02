# Kernel Vulnerabilities



## Exploiting Kernel Vulnerabilities

In order to successfully exploit kernel vulnerabilities we often have to match the vulnerable kernel version with the proper distro of Linux.&#x20;

### Enumeration

Here are some commands to figure out everything you need to know about the host system.

```shell-session
$ cat /etc/issue
Ubuntu 16.04.4 LTS \n \l
```

```shell-session
$ arch 
x86_64
```

```shell-session
$ uname -r 
4.4.0-116-generic
```

```shell-session
$ lsb_release -a
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster
```



## Searching For Vulnerabilities

We need to be specific and **PATIENT** with our searching. It's very important to figure out the main keywords for our search.

### Searchsploit

```shell-session
$ searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"  
 | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
 
 Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation     | linux/local/45010.c
```



### Google

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>
