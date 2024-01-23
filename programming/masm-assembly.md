# MASM Assembly&#x20;



## Introduction

The _**Microsoft Macro Assembler (MASM)**_ provides several advantages over inline assembly. MASM contains macro features that include loops, arithmetic, and text string processing. MASM gives you greater control over your hardware such as CPU and memory.

MASM is generally used for programming firmware, developing operating systems, and programming at system level.

### Syntax

There are several assembly syntax types, the two most important are:

#### Intel Syntax - Widely used in Windows Operating Systems. Friendly look.

<figure><img src="../.gitbook/assets/image (17).png" alt="" width="375"><figcaption></figcaption></figure>

#### AT\&T Syntax - Generally used in Unix Systems. Default for GDB debugger.

<figure><img src="../.gitbook/assets/image (16).png" alt="" width="375"><figcaption></figcaption></figure>

{% embed url="https://www.amazon.com/Art-64-Bit-Assembly-Language/dp/1718501080" %}
Recommended&#x20;
{% endembed %}

## Introduction to Registers

CPU Registers are small, high-speed storage locations within the CPU used to store data and addresses during the execution of instructions. _<mark style="color:yellow;">**Registers are the single place where mathematical functions (additions, multiplication, subtractions) can be carried out. Registers often hold pointers that refer to the memory.**</mark>_

### Types of Registers

CPU registers can mainly be classified into 4 different categories.

* **General Purpose Registers**
* #### Segment Registers
* #### Special purpose application-accessible registers
* **Special Purpose Kernel-Mode Registers**



In this page we will only go over general purpose registers since their commonly used by programmers.

## General Purpose Registers

Used to store temporary data. It's content can be accessed by assembly programming. Numbered: R0, R1, R2,...Rn-1.



### Windows x86 Architecture

{% embed url="https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture#registers" %}

In Windows x86 the general purpose registers look like this:

| 32-bits | 16-bits | 8-bits  |
| ------- | ------- | ------- |
| EAX     | AX      | AH / AL |
| EBX     | BX      | BH / BL |
| ECX     | CX      | CH / CL |
| EDX     | DX      | DH / DL |
| ESI     | SI      | SIL     |
| EDI     | DI      | DIL     |
| EBP     | BP      | BPL     |
| ESP     | SP      | SPL     |
| R8D     | R8W     | R8L     |
| R9D     | R9W     | R9L     |
| R10D    | R10W    | R10L    |
| R11D    | R11W    | R11L    |
| R12D    | R12W    | R12L    |
| R13D    | R13W    | R13L    |
| R14D    | R14W    | R14L    |
| R15D    | R15W    | R15L    |

### x86 Register Structure

The following diagram shows the first two registers. EAX & EBX.&#x20;

<figure><img src="../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### Windows x64 Architecture

{% embed url="https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture#registers" %}

In Windows x64 the general purpose registers look like this:&#x20;

| 64-bits | 32-bits | 16-bits | 8-bits  |
| ------- | ------- | ------- | ------- |
| RAX     | EAX     | AX      | AH / AL |
| RBX     | EBX     | BX      | BH / BL |
| RCX     | ECX     | CX      | CH / CL |
| RDX     | EDX     | DX      | DH / DL |
| RSI     | ESI     | SI      | SIL     |
| RDI     | EDI     | DI      | DIL     |
| RBP     | EBP     | BP      | BPL     |
| RSP     | ESP     | SP      | SPL     |
| R8      | R8D     | R8W     | R8B     |
| R9      | R9D     | R9W     | R9B     |
| R10     | R10D    | R10W    | R10B    |
| R11     | R11D    | R11W    | R11B    |
| R12     | R12D    | R12W    | R12B    |
| R13     | R13D    | R13W    | R13B    |
| R14     | R14D    | R14W    | R14B    |
| R15     | R15D    | R15W    | R15B    |

### x64 Register Structure

The following diagram shows the first two registers. RAX & RBX.

<figure><img src="../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

#### <mark style="color:red;">IMPORTANT:</mark> It's important to note that structure of these registers are not independent. They are arranged in a hierarchical structure. Where registers of larger size overlay smaller ones. RAX (64 bit) overlays EAX (32 bit), which in turn overlays the 16 bit registers (AX & AH/AL).

**Therefore, modifying the value of RAX will change the value of EAX, and therefore the values of AX. **<mark style="color:yellow;">**The hierachical relationship implies that changing the values of higher registers effects the value of lower registers, vice versa.**</mark>

For example, modifying the value of `BL` will impact the value of `BX`, which will then influence the value of `EBX`, and subsequently modify the value of `RBX`.



## Volatile vs Non-Volative Registers

During a function or procedure call (assembly functions are called procedures), certain registers automatically change value. These are called non-volatile registers.

{% embed url="https://www.techopedia.com/definition/8591/non-volatile-register" %}

_**Common Non-Volatile registers:**_

* x64 Systems - `RSP`, `RSI`, `RDI`, `RBP`, `RBX`, `R12-15`.
* x86 Systems - `EBX`, `EBP`, `ESI`, `EDI`, `R12-R15D`.

On the other hand, volatile registers do not need to be saved across a function/procedure call:

* x64 Systems - `RCX`, `RAX`, `RDX`, `R8-11`.
* x86 Systems - `ECX`, `EAX`, `EDX`, `R8-11D`.

_<mark style="color:red;">**IMPORTANT:**</mark>_ Whenever a value of a non-volatile register is changed by the routine (procedure), the old value has to be saved on the stack prior to changing the register and that value has to be restored before returning.



## RSP & RIP Registers

The _**RIP**_ register on 64-bit systems and the _**EIP**_ on 32-bit systems, is a _**special-purpose register**_ that holds the memory address of the next instruction being executed. The processor automatically increments the RIP/EIP register after executing each instruction.

The _**RSP/ESP**_ register is called the _**stack pointer register**_. It holds the memory address of the top of the stack. (The stack is a memory region that's used to store temporary data & function call information. The RSP/ESP keeps track of the stacks current location).



## RFLAGS Register

The _**RFLAGS**_ (Register Flags) is a special-purpose register that _**contains several status and control flags that are used by the processor to control program execution.**_&#x20;

64-bit machines the RLAG is 64 bits in size, 32-bit: 32 bits. The register comprises several single-bit values, where each bit corresponds to a single flag. A flag is set to 1 when activated and 0 when deactivated.&#x20;

IMPORTANT: The majority of RFLAGS flags are reserved for kernel-mode functions, they are limited to general users.

<figure><img src="../.gitbook/assets/image (21).png" alt=""><figcaption><p>Where each bit in the 32bit register is reserved to a indiviual flag.</p></figcaption></figure>

_**The relevant flags are explained below:**_

* **Carry Flag (CF) -**- This flag is set when an arithmetic operation generates a carry or borrow. It is also used in bitwise operations, where it indicates whether the result of the operation has a carry-out from the most significant bit.
* **Parity Flag (PF)** - This flag is set when the least significant byte of the result of an arithmetic operation has an even number of set bits.
* **Zero Flag (ZF)** - This flag is set when the result of an arithmetic operation is zero.
* **Sign Flag (SF)** - This flag is set when the result of an arithmetic operation is negative.
* **Overflow Flag (OF)** - This flag is set when an arithmetic operation generates a signed overflow, meaning that the result is too large to be represented in the available number of bits.



## MASM Assembly Program Structure

Here is a typical MASM program, the semicolon `;` denotes a comment.

```nasm
; Data section: contains variable and memory values, adding this section is optional 
; Variables can be declared below the ".data" directive
.data


; Code section: contains the assembly code/functions
; Assembly functions can be declared below the ".code" directive
.code


; MASM function declaration
main PROC ; Start of function "main"
     
      ; Assembly code of "main"
      
      ret ; Return from "main"     
main ENDP ; End of function "main"    


; The "end" directive marks the end of the source file
end
```



### Declaring Variables

<mark style="color:yellow;">**Variables must be declared within the .data section of the program.**</mark>

```
VarName directive VarValue
```

**VarName** is the variable name you want.&#x20;

Here is a list of possible directives:&#x20;

* `word` - Unsigned 16-bit value (word).
* `sword` - Signed 16-bit integer value.
* `dword` - Unsigned 32-bit value (double word).
* `sdword` - Signed 32-bit integer value.
* `qword` - Unsigned 64-bit value (quad word).
* `sqword` - Signed 64-bit integer value.
* `oword` - 128-bit value (octal word).
* `tbyte` - Unsigned 80-bit value.
* `real4` - 32-bit floating point value.
* `real8` - 64-bit floating point value.
* `real10` - 80-bit floating point value.
* `byte` - Unsigned 8-bit value.
* `sbyte` - Signed 8-bit integer value.

**Declaring Value:**

**VarValue** is our value:

```nasm
WordVariable      word         2
sWordVariable     sword       -2
FloatVariable     real8       3.1
```

**Declaring value as Hexadecimal:**

We can initialize a value with hexadecimal using the `h` suffix.

```nasm
DwordVariable     dword       10h         ; this is 10 in hex, which is 16 in decimal
```

#### Declaring Strings:

Strings are declared using byte directive

```nasm
StringVar  byte 'This is a string', 0    ; we add "0" to null-terminate the string 
```

**The MASM assembler interprets the above string as an array of hexadecimal characters. We can incorprate a new line character `\n` as hexademical: `10`**

```nasm
StringVar byte 'This is a string with a new line', 10, 0  ; "10" represents the new line character and is equal to 16 in decimal format
```

Since the `byte` directive in MASM assumes that it is dealing with hexadecimal characters, it is unnecessary to include the `h` suffix to represent the value of 10.



## Assembly Instructions

The following section goes over common Assembly instructions. A full list can be found:

{% embed url="https://www.felixcloutier.com/x86/" %}
Refer to the intel 64 architecture software developer manual
{% endembed %}



### mov instruction

The **`mov`** instruction is the most frequently used instruction in assembly. As the name suggests, it is used to move data between registers or memory locations.

```nasm
mov destination, source
```

Both destination or source can be a general purpose register or memory variable. **The mov instruction is limited to:**

* Only one of the source and destination operands can be a memory variable.
* Both the source and destination operands must be of the same size. Mixing different operand sizes within a single `mov` instruction will result in a compilation error.

_**Here is a list of all legal mov instructions**_

<figure><img src="../.gitbook/assets/image (22).png" alt=""><figcaption><p>In T<em>he Art of 64-Bit Assembly Language</em> book</p></figcaption></figure>

```nasm
mov rax, 1234     ; move the value 1234 into the RAX register
mov rax, rbx      ; move the value in the RBX register into the RAX register

mov al, 5h        ; move the value 0x05 into the AL register
mov [ebx], al     ; move the value in AL to the memory location pointed to by the EBX register
```

In assembly language, square brackets `[]` are utilized to indicate indirect memory access. It points to the source of the memory location. Similar to pointers in C.



### add & sub instructions

add & sub insturctions adds and subtracts to operands. They share the same syntax.

```nasm
add destination, source ; destination = destination + source
sub destination, source ; destination = destination + source
```

```nasm
add rax, rbx      ; add the value in RBX to the value in RAX and store the result in RAX
add rax, [rcx]    ; add the value in the memory location at RCX to the value in RAX and store the result in RAX
add [rax], 10     ; add the value 10 to the memory location at RAX and store the result in that memory location

mov al, 12h       ; move the value 0x12 into the AL register
mov bl, 5h        ; move the value 0x05 into the BL register
sub al, bl        ; subtract the value in BL from the value in AL and store the result in AL. AL's value is now '13'
```



### call & ret instructions

