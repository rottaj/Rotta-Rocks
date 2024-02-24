# Fixing Memory Permissions



## Introduction

When executing a PE in memory, several different sections of the PE require different types of permissions. We can iterate through each section and determine what privileges are needed to be set in order for execution to occur successfully.



## Setting Correct Memory Permissions

The `IMAGE_SECTION_HEADER.Characteristics` can be used to determine the appropriate memory permissions to set for each specific PE section. Here are the values:

* `IMAGE_SCN_MEM_EXECUTE` - This indicates that the section can be executed as code.
* `IMAGE_SCN_MEM_READ` - This indicates that the section can be read.
* `IMAGE_SCN_MEM_WRITE` - This indicates that the section can be written to.

<mark style="color:yellow;">**NOTE:**</mark> `IMAGE_SECTION_HEADER.Characteristics` is a [bitfield](https://www.geeksforgeeks.org/bit-fields-c/) so it can contain more than one flag at a time. Checking for flags must be done via the AND (`&`) operator and not the equality (`==`) operator.

{% code fullWidth="true" %}
```c
BOOL FixMemPermissions(IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) {

	// Loop through each section of the PE 
	for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		// Variables to store the new and old memory protections.
		DWORD	dwProtection		= 0x00;
		DWORD   dwOldProtection		= 0x00;

		// Skip the section if it has no data or no associated virtual address.
		if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress)
			continue;

		// Determine memory protection from characteristics.
		// readable, writable, executable

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READ;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;

		// Apply the determined memory protection to the section.
		if (!VirtualProtect((PVOID)(pPeBaseAddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData, dwProtection, &dwOldProtection)) {
		        wprintf(L"VirtualProtect Failed %d\n", GetLastError());
			return FALSE;
		}
	}

	return TRUE;
}
```
{% endcode %}

## Reference

{% embed url="https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/" %}
