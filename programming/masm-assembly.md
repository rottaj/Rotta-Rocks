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

**Therefore, modifying the value of RAX will change the value of EAX, and therefore the values of AX.&#x20;**<mark style="color:yellow;">**The hierachical relationship implies that changing the values of higher registers effects the value of lower registers, vice versa.**</mark>

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

The _**RIP/EIP**_ register is a _**special-purpose register**_ that holds the memory address of the next instruction being executed. The processor automatically increments the RIP/EIP register after executing each instruction.

The _**RSP/ESP**_ register is called the _**stack pointer register**_. It holds the memory address of the top of the stack. (The stack is a memory region that's used to store temporary data & function call information. The RSP/ESP keeps track of the stacks current location).



## RDI, RSI, RDX  Argument Registers

The general purpose registers rdi, rsi, rdx, rcx, r8, and r9 are typically used for parameter passing. These registers are known as "Arguments registers", they hold values that are passed to a function.

```c
int result = add(3,6);
```

In the example above, the values 3 and 6 would be passed to the add function using registers. **rdi might hold 3 and rsi might hold 6.**



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



### mov&#x20;

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



### add & sub&#x20;

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



### call & ret&#x20;

Procedure calls are made with the **`call`** instruction. The **`ret`** instruction is then used to return execution back to the caller, which serves a similar purpose as C/C++.

```nasm
call  ProcedureName  ; ProcedureName is the function name we call.
```

The **`ret`** instruction does not require any parameters / operands. It does not return any value, it's purpose is to indicate that the current function is finished executing. The address that is returned from **`ret`** is determined by the value at the top of the stack.

```nasm
ret
```

#### Example code

Here is an example of **`ret`** & **`call`** instructions.

```nasm
.code

DummpProc     PROC
      mov rcx, 3        ; dummy code
      add rbx, 2
      sub esi, 1
      ret               ; return execution back to "main"
DummpProc     ENDP


main          PROC
      call DummpProc    ; calling "DummpProc"
      ret               ; function "main" is terminated
main          ENDP

end
```

### lea&#x20;

The Load Effective Address (lea) instruction returns the memory address of a location and load it into a register, without actually accessing the memory itself. It's essentially the _**`&`**_ **address-of** operator in C/C++.&#x20;

```nasm
lea reg64, source  ; reg64 represents a 64-bit general-purpose register
```

Where `reg64` (the destination operand) represents any **64-bit general-purpose register** that will hold the address of the source memory location.

```nasm
StringVar byte 'String Variable', 0       ; A dummy string variable 
lea rcx, StringVar                        ; Load the address of the StringVar variable into RCX. RCX is now equal to &StringVar[0]
```



### and, or, xor, not

The logical operators **`and`**, **`or`**, **`xor`**, and **`not`** are all used to perform logical operations on bits.

#### and

The **`and`** instruction performs a bitwise and **operation** between two operands and stores the result in the destination operand.

```nasm
and destination, source
```

#### or

The `or` instruction performs a _bitwise or operation_ between two operands and stores the result in the destination operand.

```nasm
or destination, source
```

#### xor

The `xor` instruction performs an _exclusive OR operation_ between two operands and stores the result in the destination operand. One common use of the `xor` instruction is to clear a register, which is achieved by XORing the register with itself. The syntax of the `xor` instruction is as follows:

```
xor destination, source
```

**not**

The `not` instruction performs a _bitwise not operation_ on the operand and stores the result in the destination operand. The syntax of the `not` instruction is as follows:

```
not destination
```

### jmp

The **`jmp`** instruction, jumps to the destination operand. It can be a memory address, register, or a label. It's used for unconditional branching or jumping.

```
jmp   destination       ; Where 'destination' is where to jump 
```

<mark style="color:red;">**NOTE:**</mark> In assembly language, a <mark style="color:yellow;">**label**</mark> is a name given to a specific location in the program's code, which is usually defined using a colon (`:`) at the end of a name or identifier.

**Example jmp**

```nasm
.code

main PROC
      add eax, 2              ; dummy code
      xor ax, 5
      mov bx, ax
      jmp LabelName           ; Jump to execute 'LabelName' 
      mov eax, 100            ; These instructions won't get executed
      mov ebx, 100
LabelName:
      xor eax, eax            ; LabelName's code
      sub ebx, 2      
      ret
main ENDP

end
```



### jz & jnz

jz and jnz instructions are conditional jump instructions, which allow for conditional execution of code. <mark style="color:yellow;">**These instructions work by checking a specified flag in the RFLAGS register.**</mark>

`jz`, which stands for "jump if zero", jumps if the zero flag is set (1), while `jnz` ("jump if not zero") executes the jump if the zero flag is clear (0). There are many other conditional jump instructions:

* `jc` _Jump if Carry_ - Executes the branch if the Carry Flag is set (1).
* `jnc` _Jump if Not Carry_ - Executes the branch if the Carry Flag is not set (0).
* `jo` _Jump if Overflow_ - Executes the branch if the Overflow Flag is set (1).
* `jno` _Jump if Not Overflow_ - Executes the branch if the Overflow Flag is not set (0).
* `js` _Jump if Sign_ - Executes the branch if the Sign Flag is set (1).
* `jns` _Jump if Not Sign_ - Executes the branch if the Sign Flag is not set (0).
* `je` _Jump if Equal_ - Executes the branch if the Zero Flag is set (1).
* `jne` _Jump if Not Equal_ - Executes the branch if the Zero Flag is not set (0).
* `ja` _Jump if Above_ - Executes the branch if the left operand is greater than the right operand.
* `jae` _Jump if Above or Equal_ - Executes the branch if the left operand is greater than or equal to the right operand.
* `jb` _Jump if Below_ - Executes the branch if the left operand is less than the right operand.
* `jbe` _Jump if Below or Equal_ - Executes the branch if the left operand is less than or equal to the right operand.



### cmp&#x20;

The **`cmp`** instruction or "compare" is the most useful instruction to execute prior to a conditional jump instruction.

```
cmp First, Second
```

The `cmp` instruction subtracts the second operand from the first operand and sets the condition code flags based on the result of the subtraction. NOTE: It does not store the difference back into the first (destination).

The following examples demonstrate how `cmp` can set a flag's value based on the value of its operands.

* If the first operand is greater than the second operand, the Carry flag is cleared and the Sign flag is set if the result is negative.
* If the second operand is greater than the first operand, the Carry flag is set and the Sign flag is cleared.
* If the two operands are equal, the Zero flag is set and the Carry and Sign flags are cleared.



#### The `cmp` instruction is usually used in conjuction with a jmp. Here's an example of dissembled C code:

```c
#include <stdio.h>

int main() {

	int i = rand();
	// if "i" is not equal to 10
	if (i != 10) {
		printf("i != 10 \n");
	}

	return 0;
}
```

<figure><img src="../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

The following assembly code shows a `je` instruction being found directly below a `cmp` instruction.



### push & pop&#x20;

The push and pop instructions are used to manipulate the stack.&#x20;

**`push`** takes a value from a register and pushed it onto the top of the stack.

```
push Source
```

pop takes the value at the top of the stack and pops it off, storing it in the destination register or memory location.

```
pop Destination
```

### leave

The **`leave`** instruction is used to clean up or exit a subroutine or function.

&#x20;When executed, it first moves the value of the base pointer register (`RBP`) to the stack pointer register (`RSP`). It then pops the value of the base pointer register from the stack, restoring it to its previous value.

Essentially, the `leave` instruction performs the same task as the following instructions:

```
mov rsp, rbp
pop rbp
```



## Memory Access Specifiers

In assembly, memory access specifiers are used to determine the size and the type of data being accessed in memory. These specifiers act like type-casting in a programming language.

The most commonly used Memory Access Specifiers are:

### Q**uadword Pointer - qword ptr**

A quadword pointer is used to access a 64-bit data value stored in memory. It is specified using the `qword ptr` specifier. For instance, if you want to access a 64-bit integer value stored in a particular memory location, you can use the `qword ptr` specifier with the `mov` instruction. Here are two examples:

```
mov rax, qword ptr [rbx]         ; Example 1
mov rax, qword ptr [rsp + 32h]   ; Example 2
```

In the first example, the 64-bit integer value stored at the memory location pointed to by the `rbx` register is accessed using the `qword ptr` specifier with the `mov` instruction. In the second example, the `qword ptr` specifier is used with the `mov` instruction to access the 64-bit integer value stored at an offset of `32h` bytes from the `rsp` register.

### D**oubleword Pointer - dword ptr**

A doubleword pointer is a memory addressing mode that specifies the size of 32-bit data in memory. It is used when manipulating data stored in memory, particularly 32-bit integer values. To access a 32-bit integer value stored at a specific memory location, the `dword ptr` specifier should be used in the instruction, as shown in the following examples:

```
mov dword ptr [ebx], 12345678	; Example 1: stores a 32-bit integer value in memory
mov eax, dword ptr [edx + 4]	; Example 2: loads a 32-bit integer value from memory into the eax register
```

### B**yte Pointer - byte ptr**

A byte pointer is used to indicate the size of 8-bit data in memory. To access a single byte of data stored at a specific memory location, the byte ptr specifier is used.

```
mov al, byte ptr [edx + 2]	; Example 1	
mov byte ptr [ebx + 8], 55h	; Example 2	
```



## Calling Functions

Calling functions in assembly can happen a couple ways:



### Calling assembly function via call

1.) Calling the assembly function via call instruction with ret used to return the caller.

```nasm
call power

power:
        push ebp                # save old base pointer
        mov esp, ebp           # make stack pointer the base pointer

```

### Calling the assembly function from C

We can import an assemly function to a C file. The function prototype is defined with the **`extern`** keyword. This informs the compiler that the function is already in another file, such as an **`.asm`** file.

_**Example of calling assembly from C:**_

```c
/*
      main.c file
*/

#include <stdio.h>

extern void SimpleAsmFunc(); // SimpleAsmFunc's prototype. Parameters and function return data type is covered in a later section

int main (){
      printf("[i] Calling 'SimpleAsmFunc' ... ");
      SimpleAsmFunc();
      printf("[+] Done");
      return 0;
}
```

```nasm
; The asm file that includes the definition of 'SimpleAsmFunc'

.code

SimpleAsmFunc PROC
      xor rcx, rcx      ; SimpleAsmFunc's code
      add rcx, 2
      ret
SimpleAsmFunc ENDP

end
```

### Calling a C function from within an assembly file.

To do this, the assembly code must first declare the C function using the externdef directive. This tells the MASM assembler that the function is in another file.

```
externdef symbol_name:type
```

Here the **`externdef`** is the name of the function and the **`type`** specifies the function type.

```
externdef foo:proc	; This will tell MASM that "foo" is a procedure
```

_**Example calling C code from assembly:**_

```c
/*
      main.c file
*/

#include <stdio.h>

// Dummy C function
void SimpleCFunc() {

	int i = 100;
	i = i * (i + 7) >> 3;
	i += i/2;

	if (i > 100)
	   i -= 20;
        else
	   i += 20;
}


int main() {
	// You can port "AsmFunc" here and call it
	return 0;
}
```

```
; The asm file that calls 'SimpleCFunc'

externdef SimpleCFunc:proc 	; Using externdef to declare "SimpleCFunc" as a procedure defined in an other file

.code 

AsmFunc PROC

      call SimpleCFunc		; Calling SimpleCFunc
      ret

AsmFunc ENDP

end
```



## Passing Parameters

The first four parameters (if they exist) are passed through the registers `RCX`, `RDX`, `R8`, and `R9`.

_<mark style="color:red;">**NOTE:**</mark>_ If a procedure requires more than four parameters, they are pushed onto the stack. These parameters are known as **stack parameters**, and the stack must be 16-byte aligned to accommodate them.&#x20;

<mark style="color:red;">**IMPORTANT**</mark>: The first stack parameter (5th procedure parameter) is located at a specific offset from the `rsp` register, depending on the function's [calling convention](https://learn.microsoft.com/en-us/cpp/cpp/calling-conventions?view=msvc-170). In a 64-bit MASM function, the fifth parameter is usually located at an offset of `[rsp + 40].`

_**Example passing parameters:**_

```nasm
AsmFunc11Parms PROC

    ; RCX => Parm1
    ; RDX => Parm2
    ; R8  => Parm3
    ; R9  => Parm4

    mov rax, qword ptr [rsp + 40]  ; Parm5
    mov rax, qword ptr [rsp + 48]  ; Parm6
    mov rax, qword ptr [rsp + 56]  ; Parm7
    mov rax, qword ptr [rsp + 64]  ; Parm8
    mov rax, qword ptr [rsp + 72]  ; Parm9
    mov rax, qword ptr [rsp + 80]  ; Parm10
    mov rax, qword ptr [rsp + 88]  ; Parm11

    ret

AsmFunc11Parms ENDP
```

Calling `AsmFunc11Parms` from C is done below

```c
#include <Windows.h>

extern int AsmFunc11Parms(PVOID Parm1, PVOID Parm2, PVOID Parm3, PVOID Parm4, PVOID Parm5, PVOID Parm6, PVOID Parm7, PVOID Parm8, PVOID Parm9, PVOID Parm10, PVOID Parm11);

int main() {
	AsmFunc11Parms(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
	return 0;
}
```



## Returning Value

When assembly returns a value it is stored in the **`RAX`** register. Before executing the **`ret`** instruction, the procedure saves the value inside the **`RAX`** register. Allowing the function to return a value.

\
The following `AddtwoNumbers` procedure, takes two parameters, to return their sum.

```
AddtwoNumbers PROC
    mov rax, rcx    ; Moving the 1st parmeter to RAX  
    add rax, rdx    ; Add the 2nd parmeter to the value in RAX
    ret             ; return (RAX here is RCX + RDX)
AddtwoNumbers ENDP
```
