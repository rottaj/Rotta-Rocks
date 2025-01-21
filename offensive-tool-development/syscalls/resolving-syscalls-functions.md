# Resolving Syscalls (Functions)



## Get Syscall number by name

Syscalls numbers vary from version to version. This code snippet is from MDSec's [blog post](https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/) to fetch the syscall number given it's name.

<pre class="language-c"><code class="lang-c"><strong>#include &#x3C;windows.h>
</strong><strong>#include &#x3C;winternl.h>
</strong>
int GetSsnByName(char* syscall) {
    PPEB_LDR_DATA Ldr = (PPEB_LDR_DATA)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
    PLIST_ENTRY Head = (PLIST_ENTRY)&#x26;Ldr->Reserved2[1];
    PLIST_ENTRY Next = Head->Flink;

    while (Next != Head) {
        LDR_DATA_TABLE_ENTRY* ent = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
        Next = Next->Flink;
        PBYTE m = (PBYTE)ent->DllBase;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(m + ((PIMAGE_DOS_HEADER)m)->e_lfanew);
        ULONG rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        if (!rva) continue; // no export table? skip

        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(m + rva);
        if (!exp->NumberOfNames) continue;   // no symbols? skip

        PDWORD dll = (PDWORD)(m + exp->Name);

        // not ntdll.dll? skip
        if ((dll[0] | 0x20202020) != 'ldtn') continue;
        if ((dll[1] | 0x20202020) != 'ld.l') continue;
        if ((*(USHORT*)&#x26;dll[2] | 0x0020) != '\x00l') continue;

        // Load the Exception Directory.
        rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        if (!rva) return -1;
        PIMAGE_RUNTIME_FUNCTION_ENTRY rtf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(m + rva);

        // Load the Export Address Table.
        rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PDWORD functionAddresses = (PDWORD)(m + exp->AddressOfFunctions);
        PDWORD nameAddresses = (PDWORD)(m + exp->AddressOfNames);
        PWORD ordinalAddresses= (PWORD)(m + exp->AddressOfNameOrdinals);

        int ssn = 0;

        // Search runtime function table.
        for (int i = 0; rtf[i].BeginAddress; i++) {
            // Search export address table.
            for (int j = 0; j &#x3C; exp->NumberOfFunctions; j++) {
                // begin address rva?
                if (functionAddresses[ordinalAddresses[j]] == rtf[i].BeginAddress) {
                    char* api = (char*)(m + nameAddresses[j]);
                    char* s1 = api;
                    char* s2 = syscall;

                    getchar();

                    // our system call? if true, return ssn
                    while (*s1 &#x26;&#x26; (*s1 == *s2)) {
                        s1++, s2++;
                    }

                    int cmp = (int)*(PBYTE)s1 - *(PBYTE)s2;
                    if (!cmp) return ssn;

                    // if this is a syscall, increase the ssn value.
                    if (*(USHORT*)api == 'wZ') ssn++;
                }
            }
        }
    }
    return -1; // didn't find it.
}

</code></pre>
