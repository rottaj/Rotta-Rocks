# code\_seg



## Introduction

The code\_seg pragma directive is used to specify the segment within the .text section in which the specified function should be stored. These sections can then be ordered using [alphabetical values](https://devblogs.microsoft.com/oldnewthing/20181107-00/?p=100155) e.g `.text$a`.

&#x20;This is possible because the linker takes the section names and splits them at the first dollar sign, the value after it is then used to sort the sections which facilitates the alphabetical ordering.&#x20;

{% embed url="https://learn.microsoft.com/en-us/cpp/preprocessor/code-seg?view=msvc-170" %}

This can be useful for when specifiying functions in order to determine the end of a file. For example: see "User Defined Reflective Loader (UDRL)".

## Example

```c
// pragma_directive_code_seg.cpp
void func1() {                  // stored in .text
}

#pragma code_seg(".text$a")
ULONG_PTR WINAPI ReflectiveLoader(VOID) {
}

#pragma code_seg(".text$b")

#pragma code_seg(".my_data1")

void func2() {                  // stored in my_data1
}


#pragma code_seg(push, r1, ".my_data2")
void func3() {                  // stored in my_data2
}

#pragma code_seg(pop, r1)      // stored in my_data1
void func4() {
}

int main() {
}
```
