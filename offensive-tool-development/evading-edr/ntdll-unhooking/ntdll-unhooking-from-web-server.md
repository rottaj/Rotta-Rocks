# NTDLL Unhooking - From Web Server

## Introduction

Another way to get a clean ntdll is from fetching it from a webserver. We can use [`Winbindex`](https://winbindex.m417z.com/) which contains almost all ntdll.dll versions.

####

## Fetching from Winbindex

### Determining Winbindex's URL Format

Because `ntdll.dll` must be fetched programmatically, it's important to understand how download links are formatted. Analyze the 3 URLs below:

1. [https://msdl.microsoft.com/download/symbols/ntdll.dll/494079D61ee000/ntdll.dll](https://msdl.microsoft.com/download/symbols/ntdll.dll/494079D61ee000/ntdll.dll)
2. [https://msdl.microsoft.com/download/symbols/ntdll.dll/2EEE8BDD1ee000/ntdll.dll](https://msdl.microsoft.com/download/symbols/ntdll.dll/2EEE8BDD1ee000/ntdll.dll)
3. [https://msdl.microsoft.com/download/symbols/ntdll.dll/F2E8A5AB214000/ntdll.dll](https://msdl.microsoft.com/download/symbols/ntdll.dll/F2E8A5AB214000/ntdll.dll)

<figure><img src="../../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

* "**1ee000**" in the URL, is 2023424 in decimal.&#x20;
* "**2023424**" is NTDLL's VirtualSize (`OptionalHeader->SizeOfImage`)
* "**494079D6**", which is 1228962262 in decimal, is the timestamp of the file. (`NtHeadeers->FileHeader->TimeDateStamp`)



### Verifying URL with Installed Windows Version

Our Pwnbox is running Windows 10 version 22H2

<figure><img src="../../../.gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>

On WinIndex the URL for NTDLL is the following:

[https://msdl.microsoft.com/download/symbols/ntdll.dll/392158001f8000/ntdll.dll](https://msdl.microsoft.com/download/symbols/ntdll.dll/392158001f8000/ntdll.dll)

* **39215800**: Timestamp (in Hexadecimal)
* **1f8000**: Size of Image (in Hexadecimal)

**Verify on Pwnbox:**

<figure><img src="../../../.gitbook/assets/image (98).png" alt=""><figcaption></figcaption></figure>



### Concat

```
#define BASE_URL L"https://msdl.microsoft.com/download/symbols/ntdll.dll/"

wsprintfW(pwUrl, L"%s%X%X/ntdll.dll", BASE_URL, dwTimeStamp, dwSizeOfImage);
```
