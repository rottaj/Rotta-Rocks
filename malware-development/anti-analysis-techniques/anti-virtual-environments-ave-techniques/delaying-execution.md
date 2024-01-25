---
description: >-
  This page showcases functions that can be used to delay execution of a payload
  if a sandbox is detected.
---

# Delaying Execution

## Introduction

One of the most well known methods of Anti-Virtualization is to delay the execution of the program. Sandboxes typically have time constraints that prevent them from analyzing a binary for a long duration. Therefore, we can introduce a pause that will force the sandbox to terminate.

## Detecting Fast-Forwards

### What are fast-forwards?

Delaying execution of a program has been a technique used by malware developers for a while, so the majority of solutions have implemented mitigations to counter execution delays. **One technique is to fast-forward the delay duration, either by changing the parameter passed to the hooked API function or by another method.**&#x20;



## Determining Delay

**Verifying a delay has occurered can be achieved with** [`GetTickCount64`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64) **WINAPI.**

```cpp
ULONGLONG GetTickCount64();
```

Retrieves the number of milliseconds that have elapsed since the system was started.

### Basic Example of Delay Function

A basic delay function may look like this. The security solution can manipulate **`dwMilliSeconds`** and skip through the delay.

```c
BOOL DelayFunction(DWORD dwMilliSeconds){

  DWORD T0 = GetTickCount64();
  
  // The code needed to delay the execution for 'dwMilliSeconds' ms
  
  DWORD T1 = GetTickCount64();
  
  // Slept for at least 'dwMilliSeconds' ms, then 'DelayFunction' succeeded
  if ((DWORD)(T1 - T0) < dwMilliSeconds)
    return FALSE;
  else
    return TRUE;
}
```



## WaitForSingleObject

The [`WaitForSingObject`](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject) is used to set a specified object in singled-state or timeout state. We can use it in conjuction with an empty event created with[`CreateEvent`](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa). Since it's empty it will just wait for a time to occur.

```c
BOOL DelayExecutionVia_WFSO(FLOAT ftMinutes) {

  // converting minutes to milliseconds
  DWORD     dwMilliSeconds  = ftMinutes * 60000;
  HANDLE    hEvent          = CreateEvent(NULL, NULL, NULL, NULL);
  DWORD     _T0             = NULL,
            _T1             = NULL;
 
 
  _T0 = GetTickCount64();
  
  // Sleeping for 'dwMilliSeconds' ms 
  if (WaitForSingleObject(hEvent, dwMilliSeconds) == WAIT_FAILED) {
    printf("[!] WaitForSingleObject Failed With Error : %d \n", GetLastError());
    return FALSE;
  }

  _T1 = GetTickCount64();

  // Slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_WFSO' succeeded, otherwize it failed
  if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
    return FALSE;

  CloseHandle(hEvent);

  return TRUE;

}
```

The function returns `TRUE` if `WaitForSingleObject` succeeded in delaying the execution for the specified duration.

## MsgWaitForMultipleObjectsEx

The [`MsgWaitForMultipleObjectsEx`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-msgwaitformultipleobjectsex) is a nother WINAPI function we can utilize to create a delay function. It utlized the same logic as WaitForSingleObjectDelay - except it's `MsgWaitForMultipleObjectsEx`.

```c
BOOL DelayExecutionVia_MWFMOEx(FLOAT ftMinutes) {

  // Converting minutes to milliseconds
  DWORD   dwMilliSeconds    = ftMinutes * 60000;
  HANDLE  hEvent            = CreateEvent(NULL, NULL, NULL, NULL);
  DWORD   _T0               = NULL,
          _T1               = NULL;


  _T0 = GetTickCount64();
  
  // Sleeping for 'dwMilliSeconds' ms 
  if (MsgWaitForMultipleObjectsEx(1, &hEvent, dwMilliSeconds, QS_HOTKEY, NULL) == WAIT_FAILED) {
    printf("[!] MsgWaitForMultipleObjectsEx Failed With Error : %d \n", GetLastError());
    return FALSE;
  }

  _T1 = GetTickCount64();

  // Slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_MWFMOEx' succeeded, otherwize it failed
  if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
    return FALSE;

  CloseHandle(hEvent);

  return TRUE;
}
```



## NtWaitForSingleObject

We can utilize the [NtWaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntwaitforsingleobject) syscall to achieve execution delays. `NtWaitForSingleObject` is the native API version of `WaitForSingleObject`

```c
typedef NTSTATUS (NTAPI* fnNtWaitForSingleObject)(
	HANDLE         Handle,
	BOOLEAN        Alertable,
	PLARGE_INTEGER Timeout
);

BOOL DelayExecutionVia_NtWFSO(FLOAT ftMinutes) {

 	// Converting minutes to milliseconds
	DWORD                   dwMilliSeconds          = ftMinutes * 60000;
	HANDLE                  hEvent                  = CreateEvent(NULL, NULL, NULL, NULL);
	LONGLONG                Delay                   = NULL;
	NTSTATUS                STATUS                  = NULL;
	LARGE_INTEGER           DelayInterval           = { 0 };
	fnNtWaitForSingleObject pNtWaitForSingleObject  = (fnNtWaitForSingleObject)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtWaitForSingleObject");
	DWORD                   _T0                     = NULL,
	                        _T1                     = NULL;

  	// Converting from milliseconds to the 100-nanosecond - negative time interval
	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = - Delay;

	_T0 = GetTickCount64();

  	// Sleeping for 'dwMilliSeconds' ms 
	if ((STATUS = pNtWaitForSingleObject(hEvent, FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
		printf("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	_T1 = GetTickCount64();

  	// Slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtWFSO' succeeded
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	CloseHandle(hEvent);
	
	return TRUE;
}

```

## NtDelayExecution

The [`NtDelayExecution`](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FNtDelayExecution.html) is similar to the `Sleep` method. It does not need an object Handle to operate.

```c
typedef NTSTATUS (NTAPI *fnNtDelayExecution)(
	BOOLEAN              Alertable,
	PLARGE_INTEGER       DelayInterval
);

BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes) {

  	// Converting minutes to milliseconds  
	DWORD               dwMilliSeconds        = ftMinutes * 60000;
	LARGE_INTEGER       DelayInterval         = { 0 };
	LONGLONG            Delay                 = NULL;
	NTSTATUS            STATUS                = NULL;
	fnNtDelayExecution  pNtDelayExecution     = (fnNtDelayExecution)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtDelayExecution");
	DWORD               _T0                   = NULL, 
                        _T1                   = NULL;
                            
  	// Converting from milliseconds to the 100-nanosecond - negative time interval
	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = - Delay;

	_T0 = GetTickCount64();

	// Sleeping for 'dwMilliSeconds' ms 
	if ((STATUS = pNtDelayExecution(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
		printf("[!] NtDelayExecution Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	
	_T1 = GetTickCount64();

    // Slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtDE' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	return TRUE;
}
```

## Syscalls

As we know it's typically better for us to utilize syscalls and other functions that are lower to the kernel.

Do some google searches, and keep up with the latest TTPs!

{% embed url="https://undocumented.ntinternals.net/" %}
