---
description: >-
  If we have root privileges and a client that allows ssh w/ python installed we
  can use sshuttle. sshuttle however, is not a lightweight option.
---

# sshuttle

***

## Basic Usage

Sshuttle can be extremely useful for automating the execution of iptables and adding pivot rules for the remote host.&#x20;

**Running sshuttle**

```shell-session
attacker@kali$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```

To use sshuttle,  `-r` connects to a remote server with a username and password. We then include the network or IP we want to route traffic to.&#x20;

_<mark style="color:red;">**NOTE:**</mark>_ sshuttle automatically creates an entry in our iptables to redirect all traffic to the 172.16.5.0/23 network through the pivot host.

**Using Tools with Shuttle**

```shell-session
attacker@kali$ nmap -v -sV -p3389 172.16.5.19 -A -Pn
```

## Another Example

This example we set up a ssh tunnel on our jump host to a server on the internal network that has ssh enabled: `10.4.50.215:22`

```
jump-host@ubuntu$ socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

We specifying the SSH connection want to use, as well as the subnets that we want to tunnel through this connection (**10.4.50.0/24** and **172.16.50.0/24**). (The ssh connection is the tunnel on our jump host - traffic flows to 10.4.50.215:22).

```
kali@kali$ sshuttle -r database_admin@192.168.198.63:2222 10.4.198.0/24 172.16.198.0/24
```

Sshuttle is incredibly powerful because we can specify what subnets we want to tunnel our traffic through.
