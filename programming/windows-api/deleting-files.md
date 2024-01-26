---
description: Here are some functions that may be useful for reference.
---

# Deleting Files

## Delete File

{% embed url="https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deletefile" %}

## Delete File on Handle Close

We can delete a file when we close the handle. This can be a useful and quick method.

```c
#define FILE_NAME L"Testing.txt"

int wmain() {

    HANDLE hRFile = INVALID_HANDLE_VALUE;    
    
    if ((hRFile = CreateFileW(FILE_NAME, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    CloseHandle(hRFile);
```



## Self Deleting File

View "Self Deleting Malware"

{% embed url="https://app.gitbook.com/o/KN1jS9mFcRAy3dgznyeV/s/Ntkym7wd1H5AXS7YaAHH/~/changes/246/malware-development/anti-analysis-techniques/anti-debugging-techniques/self-deleting-malware" %}

