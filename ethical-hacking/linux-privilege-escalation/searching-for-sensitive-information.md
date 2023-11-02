# Searching For Sensitive Information

## Low Hanging Fruit

### env

```shell-session
$ env
...
XDG_SESSION_CLASS=user
TERM=xterm-256color
SCRIPT_CREDENTIALS=lab
USER=joe
LC_TERMINAL_VERSION=3.4.16
SHLVL=1
XDG_SESSION_ID=35
LC_CTYPE=UTF-8
XDG_RUNTIME_DIR=/run/user/1000
SSH_CLIENT=192.168.118.2 59808 22
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
MAIL=/var/mail/joe
SSH_TTY=/dev/pts/1
OLDPWD=/home/joe/.cache
_=/usr/bin/env
```

### UNIX dot files

```shell-session
$ cat .bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
export SCRIPT_CREDENTIALS="lab"
HISTCONTROL=ignoreboth
...
```

### Brute Force Other User

Once we access a low level user we can try to brute force other users while we continue to do enumerate the machine.

Create wordlist:

```shell-session
$ crunch 6 6 -t Lab%%% > wordlist
```

```shell-session
$ hydra -l eve -P wordlist 192.168.50.214 -t 4 ssh -V
```

### sudo

```shell-session
$ su - root
Password:

# whoami
root
```

```shell-session
$ sudo -i
[sudo] password for eve:

# whoami
root
```

```shell-session
$ sudo -l
[sudo] password for joe: 
Matching Defaults entries for joe on debian-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User joe may run the following commands on debian-privesc:
    (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get
```

## Inspecting Services / Daemons

### Monitor Running Processes

```shell-session
$ watch -n 1 "ps -aux | grep pass"
...

joe      16867  0.0  0.1   6352  2996 pts/0    S+   05:41   0:00 watch -n 1 ps -aux | grep pass
root     16880  0.0  0.0   2384   756 ?        S    05:41   0:00 sh -c sshpass -p 'Lab123' ssh  -t eve@127.0.0.1 'sleep 5;exit'
root     16881  0.0  0.0   2356  1640 ?        S    05:41   0:00 sshpass -p zzzzzz ssh -t eve@127.0.0.1 sleep 5;exit
```



### Capture Traffic

We capture trafffic on the feedback loop. This can reveal sensitive information and is good if we know there is a process running on localhost.

```shell-session
$ sudo tcpdump -i lo -A | grep "pass"
[sudo] password for joe:
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
...{...zuser:root,pass:lab -
...5...5user:root,pass:lab -
```



### Pspy

Pspy monitors running processes&#x20;

{% embed url="https://github.com/DominicBreuker/pspy" %}
