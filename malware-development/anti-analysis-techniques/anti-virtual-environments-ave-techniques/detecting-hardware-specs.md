---
description: >-
  Generally, virtual environments do not have full access to the host machines
  hardware. By determining the hardware specs in which our program is running we
  may be able to estimate if we're in a VM.
---

# Detecting Hardware Specs



## Anti-Virtualization Via Hardware Specs

The lack of hardware specs may determine if we're executing in a virtual machine. Though there is no guarantee of the accuracy. As the machine may have low specs.

* CPU - Check if there are fewer than 2 processors.
* RAM - Check if there are less than 2 gigabytes.
* Number of USBs previously mounted - Check if there are fewer than 2 USBs.

### CPU Check

We can check the CPU via the [GetSystemInfo](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo) WINAPI function.

{% code fullWidth="false" %}
```c
  SYSTEM_INFO   SysInfo   = { 0 };
	
  GetSystemInfo(&SysInfo);
  if (SysInfo.dwNumberOfProcessors < 2){
    // possibly a virtualized environment
  }
```
{% endcode %}

### RAM Check

We can check the amount of RAM via the [GlobalMemoryStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex) WINAPI function. The RAM storage is found through the **`uTotalPhys`** variable in the **`MEMORYSTATUSEX`** structure.

{% code fullWidth="false" %}
```c
  MEMORYSTATUSEX MemStatus = { .dwLength = sizeof(MEMORYSTATUSEX) };
  
  if (!GlobalMemoryStatusEx(&MemStatus)) {
    printf("\n\t[!] GlobalMemoryStatusEx Failed With Error : %d \n", GetLastError());
  }
  
  if ((DWORD)MemStatus.ullTotalPhys <= (DWORD)(2 * 1073741824)) {
     // Possibly a virtualized environment
  }
```
{% endcode %}

### Mounted USB Check

We can check for mounted USB's via the **`HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\USBSTOR`** registry key. Retrieving the registry key's value is done using the **`RegOpenKeyExA`** and **`RegQueryInfoKeyA`** WinAPIs.

{% code fullWidth="true" %}
```c
  HKEY    hKey            = NULL;
  DWORD   dwUsbNumber     = NULL;
  DWORD   dwRegErr        = NULL;
  
  
  if ((dwRegErr = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", NULL, KEY_READ, &hKey)) != ERROR_SUCCESS) {
    printf("\n\t[!] RegOpenKeyExA Failed With Error : %d | 0x%0.8X \n", dwRegErr, dwRegErr);
  }

  if ((dwRegErr = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwUsbNumber, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) != ERROR_SUCCESS) {
    printf("\n\t[!] RegQueryInfoKeyA Failed With Error : %d | 0x%0.8X \n", dwRegErr, dwRegErr);
  }
	
  // Less than 2 USBs previously mounted 
  if (dwUsbNumber < 2) {
    // possibly a virtualized environment
  }
  
```
{% endcode %}



## Anti-Virtualization Via Machine Resolution

In a sandbox environment, the resolution is usually set to a constant value, which may be different than a real machine. Equally, a VM may be in a window that is noticably smaller.

We can get the monitors via the [EnumDisplayMonitors](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumdisplaymonitors) WinAPI.

**EnumDisplayMonitors** requires a callback, the [GetMonitorInfoW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmonitorinfow) WinAPI must be called. The fetched information is returned as a [MONITORINFO](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-monitorinfo) structure by `GetMonitorInfoW`

After retrieving the values of the `RECT` structure, some calculations are made to determine the actual coordinates of the display:

1. `MONITORINFO.rcMonitor.right - MONITORINFO.rcMonitor.left` - This gives us the width (X value)
2. `MONITORINFO.rcMonitor.top - MONITORINFO.rcMonitor.bottom` - This gives us the height (Y value)

{% code fullWidth="true" %}
```c
// The callback function called whenever 'EnumDisplayMonitors' detects an display
BOOL CALLBACK ResolutionCallback(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lpRect, LPARAM ldata) {
	
	int             X       = 0,
	                Y       = 0;
	MONITORINFO     MI      = { .cbSize = sizeof(MONITORINFO) };

	if (!GetMonitorInfoW(hMonitor, &MI)) {
		printf("\n\t[!] GetMonitorInfoW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the X coordinates of the desplay
	X = MI.rcMonitor.right - MI.rcMonitor.left;
	
	// Calculating the Y coordinates of the desplay
	Y = MI.rcMonitor.top - MI.rcMonitor.bottom;

	// If numbers are in negative value, reverse them 
	if (X < 0)
		X = -X;
	if (Y < 0)
		Y = -Y;
	
	if ((X != 1920 && X != 2560 && X != 1440) || (Y != 1080 && Y != 1200 && Y != 1600 && Y != 900))
		*((BOOL*)ldata) = TRUE; // sandbox is detected

	return TRUE;
}


BOOL CheckMachineResolution() {

	BOOL	SANDBOX		= FALSE;
	
	// SANDBOX will be set to TRUE by 'EnumDisplayMonitors' if a sandbox is detected
	EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)ResolutionCallback, (LPARAM)(&SANDBOX));
	
	return SANDBOX;
}
```
{% endcode %}



## Anti-Virtualiation Via File Name

Sandboxs often rename filenames a method of classification. For example, they might convert the filename to it's MD5 hash equivalent. Generally resulting in a random mix of letters & numbers.

The below function counts the number of digits in the filename:

```c
BOOL ExeDigitsInNameCheck() {

	CHAR	Path			[MAX_PATH * 3];
	CHAR	cName			[MAX_PATH];
	DWORD   dwNumberOfDigits	= NULL;

	// Getting the current filename (with the full path)
	if (!GetModuleFileNameA(NULL, Path, MAX_PATH * 3)) {
		printf("\n\t[!] GetModuleFileNameA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	// Prevent a buffer overflow - getting the filename from the full path
	if (lstrlenA(PathFindFileNameA(Path)) < MAX_PATH)
		lstrcpyA(cName, PathFindFileNameA(Path));

	// Counting number of digits
	for (int i = 0; i < lstrlenA(cName); i++){
		if (isdigit(cName[i]))
			dwNumberOfDigits++;
	}

	// Max digits allowed: 3 
	if (dwNumberOfDigits > 3){
		return TRUE;
	}

	return FALSE;
}
```



## Anti-Virtualization via Number of Running Processes

We can check the number of running processes to determine is we're in a sandbox. Generally, there won't be many applications installed and will have fewer running processes.

```c
BOOL CheckMachineProcesses() {

	DWORD		adwProcesses	[1024];
	DWORD		dwReturnLen		= NULL,
			    dwNmbrOfPids		= NULL;

	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen)) {
		printf("\n\t[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	dwNmbrOfPids = dwReturnLen / sizeof(DWORD);

	// If less than 50 process, it's possibly a sandbox	
	if (dwNmbrOfPids < 50)	 
		return TRUE;

	return FALSE;
}
```



## Anti-Virtualization via User Interaction

Sandboxes are usually run in a headless environment, so there is no user interaction taking place. This can be an indicator for us that we're executing in a sandbox.

We can hook the MouseEvent to check if a mouse press occurs over a certain perioud. Let's say 5 clicks over 20 seconds.

{% code fullWidth="true" %}
```c
// Monitor mouse clicks for 20 seconds
#define MONITOR_TIME   20000 

// Global hook handle variable
HHOOK g_hMouseHook      = NULL;
// Global mouse clicks counter
DWORD g_dwMouseClicks   = NULL;

// The callback function that will be executed whenever the user clicked a mouse button
LRESULT CALLBACK HookEvent(int nCode, WPARAM wParam, LPARAM lParam){

    // WM_RBUTTONDOWN :         "Right Mouse Click"
    // WM_LBUTTONDOWN :         "Left Mouse Click"
    // WM_MBUTTONDOWN :         "Middle Mouse Click"

    if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {
        printf("[+] Mouse Click Recorded \n");
        g_dwMouseClicks++;
    }

    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}


BOOL MouseClicksLogger(){
    
    MSG         Msg         = { 0 };

    // Installing hook 
    g_hMouseHook = SetWindowsHookExW(
        WH_MOUSE_LL,
        (HOOKPROC)HookEvent,
        NULL,
        NULL
    );
    if (!g_hMouseHook) {
        printf("[!] SetWindowsHookExW Failed With Error : %d \n", GetLastError());
    }

    // Process unhandled events
    while (GetMessageW(&Msg, NULL, NULL, NULL)) {
        DefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }
    
    return TRUE;
}



int main() {

    HANDLE  hThread         = NULL;
    DWORD   dwThreadId      = NULL;

    // running the hooking function in a seperate thread for 'MONITOR_TIME' ms
    hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MouseClicksLogger, NULL, NULL, &dwThreadId);
    if (hThread) {
        printf("\t\t<<>> Thread %d Is Created To Monitor Mouse Clicks For %d Seconds <<>>\n\n", dwThreadId, (MONITOR_TIME / 1000));
        WaitForSingleObject(hThread, MONITOR_TIME);
    }

    // unhooking
    if (g_hMouseHook && !UnhookWindowsHookEx(g_hMouseHook)) {
        printf("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
    }

    // the test
    printf("[i] Monitored User's Mouse Clicks : %d ... ", g_dwMouseClicks);
    // if less than 5 clicks - its a sandbox
    if (g_dwMouseClicks > 5)
        printf("[+] Passed The Test \n");
    else
        printf("[-] Posssibly A Virtual Environment \n");


    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    return 0;
}
```
{% endcode %}
