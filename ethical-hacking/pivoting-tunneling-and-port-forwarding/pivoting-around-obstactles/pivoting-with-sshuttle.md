---
description: >-
  Sshuttl is another tool written in Python which removes the need to configure
  proxychains. NOTE: This tool only works for pivoting over SSH and does not
  provide other options (TOR & HTTPS).
---

# Pivoting with sshuttle

Sshuttle can be extremely useful for automating the execution of iptables and adding pivot rules for the remote host.&#x20;



**Running sshuttle**

```shell-session
attacker@kali$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```

To use sshuttle, we specify the option `-r` to connect to the remote machine with a username and password. Then we need to include the network or IP we want to route through the pivot host, in our case, is the network 172.16.5.0/23. _<mark style="color:red;">**NOTE:**</mark>_ this command automatically creates an entry in our iptables to redirect all traffic to the 172.16.5.0/23 network through the pivot host.\


**Traffic Routing through iptables Routes**

```shell-session
attacker@kali$ nmap -v -sV -p3389 172.16.5.19 -A -Pn
```

\
