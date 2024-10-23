# Proxychains (Linux)

Proxychains is a tool that acts as a wrapper around other applications to to tunnel traffic through a SOCKS proxy.



### Modify Proxychains .conf file

```
sudo vim /etc/proxychains.conf
```

At the end of the file we can add our SOCKS proxy

* SOCKS4:  `socks4 127.0.0.1 1080`
* SOCKS5:  `socks5 127.0.0.1 1080 myUser myPassword`

### Using Proxychains

<pre><code><strong>// For nmap we must add -Pn and -sT
</strong><strong>proxychains nmap -n -Pn -sT -p445,3389,4444,5985 192.168.1.22
</strong>proxychains wmiexec.py ROTTA/cfoxy@192.168.1.222
</code></pre>
