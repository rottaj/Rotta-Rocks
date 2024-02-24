# Patching IAT



## Introduction

When building Position Independent Code (PIC), the term patching refers to fixing import addresses when the PE is loaded into memory based on their RVA and the Image base address of the PE when it's loaded into a memory buffer.&#x20;



{% code fullWidth="true" %}
```c

BOOL FixImportAddressTable(IN PIMAGE_DATA_DIRECTORY pEntryImportDataDir, IN PBYTE pPeBaseAddress) {
    for (SIZE_T i =0; i < pEntryImportDataDir->Size; i+=sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        PIMAGE_IMPORT_DESCRIPTOR currentImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pPeBaseAddress + pEntryImportDataDir->VirtualAddress + i);

        if (currentImportDescriptor->FirstThunk == 0 && currentImportDescriptor->OriginalFirstThunk == 0)
            break;

        LPSTR cDllName = (LPSTR)(pPeBaseAddress + currentImportDescriptor->Name);
        HANDLE hModule = NULL;

        // See if we can load DLL
        hModule = LoadLibraryA(cDllName);
        if (hModule == NULL) {
            wprintf(L"Failed to Load Library %s GetLastError: %d", cDllName, GetLastError());
            return FALSE;
        }

        // Iterate through imported functions via IAT & INT
        SIZE_T     ImgThunkSize                    = 0x00;    // Used to move to the next function (iterating through the IAT and INT)
        ULONG_PTR pFuncAddress = 0;
        PIMAGE_IMPORT_BY_NAME pImgImportByName = NULL;

        while (TRUE) {

            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddress + currentImportDescriptor->FirstThunk + ImgThunkSize);
            PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddress + currentImportDescriptor->OriginalFirstThunk + ImgThunkSize);

            if (pOriginalFirstThunk->u1.Function == 0 && pFirstThunk->u1.Function == 0) {
                break;
            }

            if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {
                if ( !(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal))) ) {
                    printf("[!] Could Not Import !%s#%d \n", cDllName, (int)pOriginalFirstThunk->u1.Ordinal);
                    return FALSE;
                }
            }
                // Import function by name
            else {
                pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pPeBaseAddress + pOriginalFirstThunk->u1.AddressOfData);
                if ( !(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, pImgImportByName->Name)) ) {
                    printf("[!] Could Not Import !%s.%s \n", cDllName, pImgImportByName->Name);
                    return FALSE;
                }
            }

            // Install the function address in the IAT
            pFirstThunk->u1.Function = (ULONGLONG)pFuncAddress;

            ImgThunkSize += sizeof(IMAGE_THUNK_DATA);

        }

    }
    return TRUE;
}
```
{% endcode %}
