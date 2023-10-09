---
description: DLL Hijacking is a highly effective method.
---

# Service DLL Hijacking

## Finding DLL's on running service.

We can use Process Monitor, or any monitoring tool that is on the system to enumerate DLL's on a running service.&#x20;

_<mark style="color:red;">**NOTE:**</mark>_ If the DLL list is empty, we should restart the service and view the start up DLLs.

<figure><img src="../../../.gitbook/assets/Screenshot_20231009_180645 (1).png" alt=""><figcaption><p>XFreeRDP - Procmon w/ DLL Name Filter is Empty.</p></figcaption></figure>



### Restarting DLL Service

