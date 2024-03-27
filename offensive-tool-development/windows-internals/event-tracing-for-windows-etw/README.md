# Event Tracing for Windows (ETW)



## Introduction

Event Tracing for Windows (ETW) is a built in Windows mechanism that allows for logging events and activies that occur on the system. Events are generated in both user and kernel mode applications / drivers.

ETW is an invaluable source of information for defenders.



## ETW Architecture

ETW is compromised of 4 main components.

* **Providers:** Responsible for generating events. Can be kernel mode or user mode.
* **Tracing Sessions:** Represents a container for capturing and managing events from an ETW provider.
* **Controllers:** Responsible for managing and controller tracing sessions.
* **Consumers:** Applications that connect to ETW and read events.



### Trace Files

These files store events that are recorded by the provider. Each file is signified with **`.etl`**

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

### Providers

Providers are the highest leven entities in ETW. They are responsible for generating events and can be kernel mode drivers or user mode applications. Each provider has it's own GUID.

```powershell
logman query providers
```

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



### Tracing Sessions

Tracing Sessions are containers for capturing events from a ETW provider. A session is a kernel object that collects events in a kernel buffer and sends them to a file or real-time consumer process.

```powershell
logman query -ets
```

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



### Controllers

Controllers are responsible for managing and controller tracing sessions by allowing users to start, stop, and configure them.



### Consumers

Consumers are applications that can connect to ETW. For example: an EDR. They can read system events, network logs, and more.
