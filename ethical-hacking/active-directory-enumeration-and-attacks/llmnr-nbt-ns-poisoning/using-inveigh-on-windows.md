---
description: >-
  LLMNR & NBT-NS poisoning is possible from a Windows host as well. In the last
  section, we utilized Responder to capture hashes. This section will explore
  the tool Inveigh.
---

# Using Inveigh on Windows

### Inveigh - Overview

When we only have access to a Windows host as our attack box, the tool Inveigh works similar to Responder. Inveigh is written in powershell and C#.&#x20;

Inveigh can listen to IPv4 and IPv6 and several other protocols, including `LLMNR`, DNS, `mDNS`, NBNS, `DHCPv6`, ICMPv6, `HTTP`, HTTPS, `SMB`, LDAP, `WebDAV`, and Proxy Auth.

### Using Inveigh

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-18 091631.png" alt=""><figcaption><p>We need to use Invoke-Module to access the scripts.</p></figcaption></figure>

Let's start Inveigh with LLMNR and NBNS spoofing, and output to the console and write to a file. We will leave the rest of the defaults, which can be seen [here](https://github.com/Kevin-Robertson/Inveigh#parameter-help).

&#x20;&#x20;

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-18 091727.png" alt=""><figcaption></figcaption></figure>

We can see that we immediately begin getting LLMNR and mDNS requests. The below animation shows the tool in action.



<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-18 091921.png" alt=""><figcaption></figcaption></figure>

### C# Inveigh (InveighZero)

The PowerShell version of Inveigh is the original version and is no longer updated. There will be situations where we'll have to alternate between the two and see which works.

Let's go ahead and run the C# version with the defaults and start capturing hashes.

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-18 092029.png" alt=""><figcaption><p>The options with a <code>[+]</code> are default and enabled by default and the ones with a <code>[ ]</code> before them are disabled.</p></figcaption></figure>

We can also see the message `Press ESC to enter/exit interactive console`, which is very useful while running the tool.&#x20;

We can hit the `esc` key to enter the console while Inveigh is running.

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-18 092134 (1).png" alt=""><figcaption></figcaption></figure>

After typing `HELP` and hitting enter, we are presented with several options:\


<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-18 092749.png" alt=""><figcaption></figcaption></figure>

We can quickly view unique captured hashes by typing `GET NTLMV2UNIQUE`.\


<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-18 092929.png" alt=""><figcaption><p>Shows Unique NTLMv2 Hashes</p></figcaption></figure>

We can type in `GET NTLMV2USERNAMES` and see which usernames we have collected. This is helpful if we want a listing of users to perform additional enumeration against and see which are worth attempting to crack offline using Hashcat.

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-18 093018.png" alt=""><figcaption><p>Shows NTLMv2 Usernames</p></figcaption></figure>

Let's start Inveigh and then interact with the output a bit to put it all together.

```powershell
PS> .\Inveigh.exe
```

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-18 093106.png" alt=""><figcaption></figcaption></figure>
