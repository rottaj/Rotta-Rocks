---
description: >-
  Impacket is an expansive toolkit that provides us with many different ways to
  enumerate and interact with Windows protocols.
---

# Impacket Toolkit



## P**sexec.py**

One of the most useful tools in Impacket is psexec.py. The tool is a clone of Sysinternals psexec executable.&#x20;

\
**Using psexec.py**

To connect to a host with psexec.py, we need credentials for a user with local administrator privileges.

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  
</strong></code></pre>

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-20 153517.png" alt=""><figcaption></figcaption></figure>
