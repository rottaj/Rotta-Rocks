# PIC Checklist



## Introduction

These are some of the do's and dont's of creating Position Indpendent Code (PIC)

## Checklist

* [ ] Avoid String literals. (Use string hashing, string stacks).
* [ ] Avoid Global Variables.
* [ ] Use custom wrapped NTAPI functions
* [ ] Use intrinsic functions



## Debugging

For debugging we can Allocate a console with AllocConsole WinAPI function.

<pre class="language-c"><code class="lang-c">extern __declspec(dllexport) BOOL ReflectiveFunction() {
    fnAllocConsole _AllocConsole = (fnAllocConsole)GetProcAddressH(GetModuleHandleH(kernel32dll_CRC32), AllocConsole_CRC32);
<strong>    _AllocConsole();
</strong><strong>}
</strong></code></pre>

## List

1. **Avoid Absolute Addresses:**
   * Reason: Absolute addresses assume a fixed memory layout, which is not suitable for PIC. Use relative addressing or pointers instead.
2. **Avoid Hardcoded Offsets:**
   * Reason: Hardcoded offsets depend on specific memory locations, which may change in a PIC environment. Use calculations or indirection to access data.
3. **Avoid Global Variables:**
   * Reason: Global variables have fixed memory addresses, making them unsuitable for PIC. Use local variables or dynamically allocated memory instead.
4. **Use Relative Offsets:**
   * Reason: Relative offsets are calculated at runtime and are not dependent on specific memory addresses, making them suitable for PIC.
5. **Avoid Direct WinAPI Calls:**
   * Reason: Direct calls to WinAPI functions may not be compatible with PIC, as the addresses of these functions can vary between processes and system configurations. Use dynamic function resolution or import address table (IAT) hooking techniques.
6. **Handle String Literals Dynamically:**
   * Reason: String literals have fixed memory addresses, which can cause issues in a PIC environment. Use dynamic memory allocation or store strings in data structures that can be relocated.
7. **Avoid Hardcoded Pointers:**
   * Reason: Hardcoded pointers rely on fixed memory addresses, which can change in a PIC environment. Instead, use dynamic memory allocation or calculate pointers at runtime.
8. **Use Position-Independent Data Structures:**
   * Reason: Data structures should be designed to accommodate changes in memory layout. Avoid assumptions about the location of elements within the structure.
9. **Handle Function Pointers Dynamically:**
   * Reason: Function pointers may have fixed addresses in non-PIC code, but in a PIC environment, they may need to be resolved dynamically to ensure correct execution.
10. **Use Indirection for Data Access:**
    * Reason: Accessing data indirectly through pointers or indexes allows for flexibility in memory layout and is compatible with PIC.

Following these guidelines will help ensure that your code remains position-independent and can execute correctly regardless of its memory location.
