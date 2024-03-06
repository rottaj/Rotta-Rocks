# ETW Tools



## Introduction

This page will cover various tools used to interact with ETW.



## Logman

**Logman** is a native command-line tool for Windows. It is an _**ETW controller**_.

### Creating Tracing Sessions

```powershell
PS> logman create trace TESTING -o C:\Users\WinDev\Desktop\Output.etl -p Microsoft-Windows-Kernel-Process -ets
```

Adding the `-ets` option to the command will send commands directly to the tracing session without saving or scheduling the session for future use

![](<../../../.gitbook/assets/image (4).png>)\


### Inspecting Trace Files

Once the trace file session is created, it can be viewed in _**Event Viewer**_.

Goto -> File -> Open Saved Log -> Select "Yes"

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

Here are the events

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Clicking on an event allow you to view the details

<figure><img src="../../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>



### Stopping Tracing Session

```powershell
PS> werlogman TESTING stop -ets
```



### Querying Information&#x20;



### Query ETW Providers

```powershell
C:\Windows\system32>logman query providers

Provider                                 GUID
-------------------------------------------------------------------------------
ACPI Driver Trace Provider               {DAB01D4D-2D48-477D-B1C3-DAAD0CE6F06B}
Active Directory Domain Services: SAM    {8E598056-8993-11D2-819E-0000F875A064}
Active Directory: Kerberos Client        {BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}
Active Directory: NetLogon               {F33959B4-DBEC-11D2-895B-00C04F79AB69}
ADODB.1                                  {04C8A86F-3369-12F8-4769-24E484A9E725}
ADOMD.1                                  {7EA56435-3F2F-3F63-A829-F0B35B5CAD41}
Application Popup                        {47BFA2B7-BD54-4FAC-B70B-29021084CA8F}
Application-Addon-Event-Provider         {A83FA99F-C356-4DED-9FD6-5A5EB8546D68}
ATA Port Driver Tracing Provider         {D08BD885-501E-489A-BAC6-B7D24BFE6BBF}
```



### Query Information about an ETW Provider

```powershell
C:\Windows\system32>logman query providers Microsoft-Antimalware-Engine

Provider                                 GUID
-------------------------------------------------------------------------------
Microsoft-Antimalware-Engine             {0A002690-3839-4E3A-B3B6-96D8DF868D99}

Value               Keyword              Description
-------------------------------------------------------------------------------
0x0000000000000001  SenseRemediation
0x0000000000000002  UefiFirmware
0x0000000000000004  TCGLogs
0x0000000000000008  SenseHeartbeat
0x0000000000000010  BmFileOverwrite
0x0000000000000020  SenseOnboardingInfo
0x0000040000000000  StartRundown
0x0000080000000000  EndRundown

Value               Level                Description
-------------------------------------------------------------------------------
0x04                win:Informational    Information

PID                 Image
-------------------------------------------------------------------------------
```



### Query Running Tracing Sessions

```powershell
C:\Windows\system32>logman query -ets

Data Collector Set                      Type                          Status
-------------------------------------------------------------------------------
Circular Kernel Context Logger          Trace                         Running
Eventlog-Security                       Trace                         Running
DiagLog                                 Trace                         Running
Diagtrack-Listener                      Trace                         Running
EventLog-Application                    Trace                         Running
EventLog-System                         Trace                         Running
LwtNetLog                               Trace                         Running
Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace Trace                         Running
NetCore                                 Trace                         Running
NtfsLog                                 Trace                         Running
RadioMgr                                Trace                         Running
UBPM                                    Trace                         Running
WdiContextLog                           Trace                         Running
WiFiSession                             Trace                         Running
UserNotPresentTraceSession              Trace                         Running
CldFltLog                               Trace                         Running
SgrmEtwSession                          Trace                         Running
ScreenOnPowerStudyTraceSession          Trace                         Running
MpWppTracing-20240306-170459-00000003-ffffffff Trace                         Running
MSDTC_TRACE_SESSION                     Trace                         Running
SHS-03062024-170520-7-7f                Trace                         Running
Cloud Files Diagnostic Event Listener   Trace                         Running
MALDEV_ETW_SESSION                      Trace                         Running
```



### Query Information about a Tracing Sessions

```powershell
C:\Windows\system32> logman query RadioMgr -ets
```



## ETW Explorer

ETWExplorer is an open source tool that offers a GUI ETW Controller

{% embed url="https://github.com/zodiacon/EtwExplorer" %}

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>





## DotNetEtwConsumer

The `DotNetEtwConsumer` tool is an ETW consumer, that uses `Microsoft-Windows-DotNETRuntime` ETW provider, which has the `{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}` GUID.&#x20;

The tool makes use of the following WinAPIs:

* [StartTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew) - Used to start an event tracing session.&#x20;
* [EnableTraceEx](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex) - Used to configure how an ETW event provider logs events to a trace session.
* [OpenTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew) - Opens a handle for consuming events from an ETW real-time trace session.
* [ProcessTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace) - Delivers events from the ETW trace session to the ETW consumer.
* [StopTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-stoptracew) - Used at the end to stop a specified event tracing session. It is equivalent to the `logman stop` command.





## Reference

{% embed url="https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63" %}

{% embed url="https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101" %}

{% embed url="https://medium.com/threat-hunters-forge/threat-hunting-with-etw-events-and-helk-part-1-installing-silketw-6eb74815e4a0" %}

{% embed url="https://bmcder.com/blog/a-begginers-all-inclusive-guide-to-etw" %}
