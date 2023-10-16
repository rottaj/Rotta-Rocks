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

<figure><img src="../../../../.gitbook/assets/Screenshot 2023-09-20 153517.png" alt=""><figcaption></figcaption></figure>



## Wmiexec.py

Utilizes a semi-interactive shell where commands are executed through  [Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page). It does NOT drop any files or executables on the target host and generates fewer logs than other modules. _<mark style="color:red;">**IMPORTANT:**</mark>_ This is a more stealthy approach to execution on hosts than other tools, but would still likely be caught by most modern anti-virus and EDR systems.&#x20;

```shell-session
attacker@kali$ wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
```



<figure><img src="../../../../.gitbook/assets/Screenshot 2023-09-20 160545.png" alt=""><figcaption></figcaption></figure>
