# NtQueryInformationProcess







## Get Base Address of Remote Process

<pre class="language-c"><code class="lang-c">STARTUPINFO si = {0};
PROCESS_INFORMATION pi = {0};
PROCESS_BASIC_INFORMATION pbi = {0};
<strong>
</strong><strong>// Relies on CreateFileW for handle
</strong><strong>if (CreateProcessW(L"C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, pSi, pPi) == 0) {
</strong>    wprintf(L"CreateProcessW Failed %d", GetLastError()) ;
    return FALSE;
};
<strong>
</strong><strong>
</strong><strong>PVOID FetchRemoteBaseAddress(PPROCESS_INFORMATION pPi, PPROCESS_BASIC_INFORMATION pPbi) {
</strong><strong>
</strong>    fnNtQueryInformationProcess NtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQueryInformationProcess");
    // get target image PEB address and pointer to image base
    DWORD dwReturnLength = 0;
    LPVOID imageBase;
    NtQueryInformationProcess(pPi->hProcess, ProcessBasicInformation, pPbi, sizeof(PROCESS_BASIC_INFORMATION), &#x26;dwReturnLength);
    DWORD_PTR pebOffset = (DWORD_PTR)pPbi->PebBaseAddress + 0x10;
    ReadProcessMemory(pPi->hProcess, (LPCVOID)pebOffset, &#x26;imageBase, sizeof(LPVOID), NULL);
    return imageBase;
}

</code></pre>
