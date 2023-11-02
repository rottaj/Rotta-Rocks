# Abusing Setuid Binaries and Capabilities



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
