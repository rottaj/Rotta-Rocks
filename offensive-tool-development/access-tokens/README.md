# Access Tokens



## Introduction&#x20;

In short, an access token, is a security context under which a process and it's threads a run under. In respect the windows API, depending on which function you use typically determines what type of token you are using.

**CreateProcess**: This function is used to create a process in user mode. This process runs under the security context of the executing user.

**EPROCESS**: Once CreateProcess is called, it is passed to [EPROCESS](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess) which is run in kernel mode. This structure holds information to manage the running process.

**KPROCESS**: Within EPROCESS resides another struct called [KPROCESS](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ke/kprocess/index.htm). It holds information for the lower layer kernel. Thread scheduling stuff.



## OpenProcess()

If you've ever used OpenProcess before you've probably noticed the dwDesiredAccess flag. This is an access right that is checked against the security descriptor of the running process. If the caller has **SeDebugPrivilege** enabled, the requested access is granted. Regardless of the context of the security descriptor.



## OpenProcessToken()

