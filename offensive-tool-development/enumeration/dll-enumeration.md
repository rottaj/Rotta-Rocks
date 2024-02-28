# DLL Enumeration



## Enumerating Loaded DLLs from PEB Structure

&#x20;A processes PEB structure contains a linked list of all loaded DLL's. This struct is called: [PEB\_LDR\_DATA](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb\_ldr\_data)

```c
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

The LIST\_ENTRY:\
<mark style="color:yellow;">**NOTE:**</mark> Each item in the list is a pointer to an `LDR_DATA_TABLE_ENTRY` structure.

```c
typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
```

* **Flink**: Pointer to the first entry in the list. (The first entry is the running process example.exe)
* **Blink**: Pointer to the last entry in the list.

The LDR\_DATA\_TABLE\_ENTRY structure is defined as follows:

```c
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```



### Example:

```c
PPEB pPeb = (PPEB)__readgsqword(0x60);

PLDR_DATA_TABLE_ENTRY pFirst = (PLDR_DATA_TABLE_ENTRY )pPeb->Ldr->InMemoryOrderModuleList.Flink;
PLDR_DATA_TABLE_ENTRY pSecond = (PLDR_DATA_TABLE_ENTRY )pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink;

wprintf(L"First Entry %ls\nSecond Entry: %ls", pFirst->FullDllName.Buffer, pSecond->FullDllName.Buffer);

```



<figure><img src="../../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

<mark style="color:yellow;">**NOTE:**</mark> The second entry will always be `ntdll.dll` since it's the first DLL that is loaded into a process.
