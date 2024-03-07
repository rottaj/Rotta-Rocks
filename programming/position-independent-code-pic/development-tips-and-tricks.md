# Development Tips & Tricks



## Introduction

When developing Position Independent Code (PIC) many times you'll find yourself executing and developing in a remote process this can be tricky because it is in a difference executing process than your injection binary (inject.exe) and may not have access to a console.

## Printing in remote process

If we don't have access to a console,&#x20;

```c
VOID DebugPrintf(
    _In_ PCHAR fmt,
    ...
) {

    va_list VaListArg      = 0;
    PVOID   CallbackOutput = NULL;
    INT     CallbackSize   = 0;

    va_start( VaListArg, fmt );

    CallbackSize   = Instance->Win32.vsnprintf( NULL, 0, fmt, VaListArg );
    CallbackOutput = mHeapAlloc( CallbackSize );

    /* If memory was allocated. */
    if ( CallbackOutput )
    {
        Instance->Win32.vsnprintf( CallbackOutput, CallbackSize, fmt, VaListArg );

        va_end( VaListArg );

        Instance->Win32.OutputDebugStringA( CallbackOutput );

        MemSet( CallbackOutput, 0, CallbackSize );
        mHeapFree( CallbackOutput );
        CallbackOutput = NULL;
    }
}
```

## AllocConsole

AllocConsole() creates a new console instance in the running process. Allowing std output.

```c
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            AllocConsole();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

