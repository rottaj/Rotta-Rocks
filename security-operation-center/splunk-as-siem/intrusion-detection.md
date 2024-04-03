# Intrusion Detection



## Introduction

Threat hunting in not trivial, this page is here to provide a methodological example into finding an IOC within a given dataset.

## Ingesting Data Sources

### Searching Effectively

Certain queries in Splunk can take up time. Effective threat hunting relies on crafting efficient queries that target relevant data.

#### Our first step is to see what we can identify within the data.

Start by viewing all available sources in index:

```splunk-spl
index="main" | stats count by sourcetype
```

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>



#### View Sysmon Sourcetype

Let's see what we're dealing with by viewing Sysmon events.

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon"
```

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

Clicking the arrow allows us to view all data in the row.

#### Let's target a ComputerName

**Note:** It's effective to search for concatenated instances \*\* and non-concatenated.

```splunk-spl
index="main" ComputerName="*uniwaldo.local*"
```

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

<mark style="color:yellow;">**NOTE:**</mark> By providing ComputerName=\*name\* it is much faster. This is because we are specifying the point in where we are trying to filter from by lessening resource consumption.





## Spotting Anomalies

### Searching for Created Processes - Sysmon

Our dataset includes Sysmon events, we can retrieve a count of all Sysmon Event id's with the following query:

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" 
|  stats count by EventCode
```

**Doing so retrieves 20 different Sysmon event code ID's:**

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

We can search the Sysmon documentation and view the respective event code ID numbers and their behavior.

#### Searching for Sysmon EventCode 1 (Process Creation)

Sysmon's event code 1 signifies a created process. Let's search for it.

The following query searches for the following:

* ParentImage: The filepath that spawned the process.
* Image: The filepath to the new process.
* Description: A description of the spawned process image
* ComputerName: The name of the computer that the process spawned on.

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 
|  stats count by ComputerName, Description, ParentImage, Image
```

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

#### Searching for powershell.exe & cmd.exe

Let's try and narrow this count down and search for some low hanging fruit. We'll search for powershell.exe & cmd.exe

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") 
| stats count by ParentImage, Image
```

<mark style="color:yellow;">NOTE:</mark> It's important we add quotes (") and the a wildcard (\*) around the Image we're filtering for.

We get 622 results!

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

&#x20;`notepad.exe` to `powershell.exe` chain stands out immediately. It implies that notepad.exe was run, which then spawned a child powershell to execute a command. Let's add to the query, and this time look for `ParentImage` as notepad.exe.

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe")
 ParentImage="C:\\Windows\\System32\\notepad.exe"
```

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

**Here we discover an IOC: a web request to an external ip address.**

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>



## Building Alerts

Below is a SQL query that will go through Sysmon events and search the Callstack for UNKNOWN memory regions as well as weeding out legitimate applications to prevent false positives.\
\
Normal Sysmon process access events starts with ntdll (hosting Windows Syscalls), if the CallTrace starts with an UNKNOWN module instead of ntdll then its suspicious and may indicate a **direct syscall evasion**.

```splunk-spl
index="main" CallTrace="*UNKNOWN*" SourceImage!=*Microsoft.NET* 
CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* 
SourceImage!="C:\\Windows\\Explorer.EXE" 
| where SourceImage!=TargetImage 
| stats count by SourceImage, TargetImage, CallTrace
```

<figure><img src="../../.gitbook/assets/image (102).png" alt=""><figcaption></figcaption></figure>
