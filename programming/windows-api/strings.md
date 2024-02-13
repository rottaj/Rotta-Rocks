# Strings

## Introductions

Probably the biggest source of my frustration when working with the Windows API is dealing with strings. There are so many functions and data types used for string comparison, concatenation, and other nonsense. When I run into something I hate and don't want to experience the pain again, I will add it here.



## wcsncmp

When working with functions like SYSTEM\_PROC\_INFORMATION we will run into the use of unicode strings when enumerating process image names.

```c
if (wcsncmp(L"Teams.exe", SystemProcInfo->ImageName.Buffer, SystemProcInfo->ImageName.Length / sizeof(WCHAR)) == 0) {
       wprintf(L"Found %\n");
       Instance->targetPID = HandleToULong(SystemProcInfo->UniqueProcessId);
}
```
