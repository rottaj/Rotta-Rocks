# Patching Base Relocations





{% code fullWidth="true" %}
```c

BOOL FixReloc(IN PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir, IN ULONG_PTR pPeBaseAddress, IN ULONG_PTR pPreferableAddress) {

    // Pointer to the beginning of the base relocation block.
    PIMAGE_BASE_RELOCATION pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)(pPeBaseAddress + pEntryBaseRelocDataDir->VirtualAddress);

    // The difference between the current PE image base address and its preferable base address.
    ULONG_PTR uDeltaOffset = pPeBaseAddress - pPreferableAddress;

    // Pointer to individual base relocation entries.
    PBASE_RELOCATION_ENTRY pBaseRelocEntry = NULL;

    // Iterate through all the base relocation blocks.
    while (pImgBaseRelocation->VirtualAddress) {

        // Pointer to the first relocation entry in the current block.
        pBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1);

        // Iterate through all the relocation entries in the current block.
        while ((PBYTE)pBaseRelocEntry != (PBYTE)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock) {
            // Process the relocation entry based on its type.
            switch (pBaseRelocEntry->Type) {
                case IMAGE_REL_BASED_DIR64:
                    // Adjust a 64-bit field by the delta offset.
                    *((ULONG_PTR*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += uDeltaOffset;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    // Adjust a 32-bit field by the delta offset.
                    *((DWORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += (DWORD)uDeltaOffset;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    // Adjust the high 16 bits of a 32-bit field.
                    *((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += HIWORD(uDeltaOffset);
                    break;
                case IMAGE_REL_BASED_LOW:
                    // Adjust the low 16 bits of a 32-bit field.
                    *((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += LOWORD(uDeltaOffset);
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    // No relocation is required.
                    break;
                default:
                    // Handle unknown relocation types.
                    printf("[!] Unknown relocation type: %d | Offset: 0x%08X \n", pBaseRelocEntry->Type, pBaseRelocEntry->Offset);
                    return FALSE;
            }
            // Move to the next relocation entry.
            pBaseRelocEntry++;
        }

        // Move to the next relocation block.
        pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)pBaseRelocEntry;
    }

    return TRUE;
}
```
{% endcode %}
