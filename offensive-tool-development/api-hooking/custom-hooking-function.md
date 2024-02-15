---
description: >-
  As we know manually implementing malware techniques is the most optimal
  approach for avoiding IoC & security mechanisms.
---

# Custom Hooking Function

***

## Creating Detour Hook

A detour hook is just a jump instruction placed at the first few instructions of function we are hooking. This is called a "Trampoline".



### Assembly Instructions (64-bit)

A trampoline looks like:

```c
mov r10, pAddress  
jmp r10
```

`pAddress`: The address of our Detour function (64 bit).

Move `pAddress` to `r10` register. Jump to the memory address located in `r10` register.

### Machine Byte Code (64-bit):

```c
0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pAddress
0x41, 0xFF, 0xE2                                            // jmp r10
```

* `0x49` (REX prefix) Instruction involving a register. (use the 64-bit version of the default operand size.)
* `0xBA` is the actual opcode for the `mov` instruction.
* `0x41` (REX prefix) 64-bit register. Indicates the use of the `r8` through `r15` registers.
* `0xFF` is the actual opcode for the `jmp` instruction.

## 64-Bit Hook (API function patch):

```c
uint8_t	uTrampoline[] = {
0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun
0x41, 0xFF, 0xE2                                            // jmp r10
};

uint64_t uPatch = (uint64_t)pAddress;
memcpy(&uTrampoline[2], &uPatch, sizeof(uPatch)); // copying the address to the offset '2' in uTrampoline
```

_**NOTE:**_ We can retrieve pAddress with GetProcAddress (preferably with a custom version of GetProcAddress).

## Writing the Hook

Before overwriting the function, we need to update the memory permissions to RWX.

```c
// Changing the memory permissons at 'pFunctionToHook' to be PAGE_EXECUTE_READWRITE
if (!VirtualProtect(pFunctionToHook, sizeof(uTrampoline), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
	return FALSE;
}

// Copying the trampoline shellcode to 'pFunctionToHook'
memcpy(pFunctionToHook, uTrampoline, sizeof(uTrampoline));
```

Where `pFunctionToHook` is the address of the function to hook, and `uTrampoline` is the jump shellcode.

## Unhooking&#x20;

After the hooked function is called we want to unhook the function, the bytes that were overwritten should be restored with those that were originally there. Before we hook the function, we should store the original bytes in a buffer. `pOriginalBytes`

```c
memcpy(pFunctionToHook, pOriginalBytes, sizeof(pOriginalBytes));
```

_**Restoring permissions:**_

```c
if (!VirtualProtect(pFunctionToHook, sizeof(uTrampoline), dwOldProtection, &dwOldProtection)) {
	return FALSE;
}
```

## Full Example:

As a recap, it's always recommended, if feasible, to implement your own method of a exploitation technique. This can greatly improve your chances of bypassing security measures.

