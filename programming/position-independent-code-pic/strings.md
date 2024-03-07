# Strings

## Introduction

The use of strings in PIC code requires careful consideration due to the need to avoid hardcoded memory addresses. Here are common approaches.

When you declare a string literal in your C code, the compiler includes that string directly into the executable binary (`.data,` `.rdata`) at compile time. This means that the memory addresses of these string literals are hard-coded into the executable, making them part of the binary image itself.

<mark style="color:yellow;">**TL;DR**</mark> Since the memory addresses of string literals are hard-coded, they can lead to issues with position independence in PIC code. To address this, techniques like string hashing or using string pointers are employed to avoid directly embedding string literals with hard-coded memory addresses in the executable.

## Using Strings in PIC

When using strings in PIC code, prefer methods like string hashing or using string pointers to ensure position independence. <mark style="color:yellow;">**Always avoid the use of string literals**</mark>.

### String Hashing

<mark style="color:yellow;">**String Hashing: This is the best method**</mark>. Involves calculating a hash value for the string at compile time and passing the hash value instead of the string itself. At runtime, the hash value can be used to look up the corresponding string from a predefined table or mapping structure. This approach avoids passing the actual string directly, ensuring position independence.

```c
(fnHeapAlloc)GetProcAddressH(GetModuleHandleH(kernel32dll_CRC32), heapalloc_CRC32);
```

### String Pointers

Instead of passing the string itself, you can pass a pointer to the string. This pointer can point to a string stored in memory dynamically allocated using functions like HeapAlloc or malloc. By passing the pointer, you avoid hardcoding the string in the function call, making the code position independent.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Dynamically allocate memory for the string "test"
    char *test = (char *)malloc(strlen("test") + 1);
    if (test == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    strcpy(test, "test");

    // Dynamically allocate memory for the individual characters "T", "e", "s", "t"
    char **testStack = (char **)malloc(4 * sizeof(char *));
    if (testStack == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        free(test);
        return 1;
    }
    testStack[0] = strdup("T");
    testStack[1] = strdup("e");
    testStack[2] = strdup("s");
    testStack[3] = strdup("t");

    // Use the dynamically allocated strings
    printf("test: %s\n", test);
    printf("testStack: %s%s%s%s\n", testStack[0], testStack[1], testStack[2], testStack[3]);

    // Free dynamically allocated memory
    free(test);
    for (int i = 0; i < 4; ++i) {
        free(testStack[i]);
    }
    free(testStack);

    return 0;
}
```

### String Constants

If you have a limited set of strings that are known at compile time, you can define them as constants using #define or const char\* and pass them directly to the function. However, this approach should be used with caution as it still involves hardcoding the string values in the code. It may not be suitable for cases where strings are dynamically generated or obtained from external sources.

```c
#include <stdio.h>

// Define string constants
const char* STRING1 = "Hello";
const char* STRING2 = "World";

// Function that uses string constants
void printStrings(const char* str1, const char* str2) {
    printf("%s %s\n", str1, str2);
}

int main() {
    // Pass string constants to the function
    printStrings(STRING1, STRING2);
    return 0;
}
```



### String Macros

Using `#define` to create string constants does not hardcode memory addresses directly into the compiled binary. When you use `#define` to define a string constant like `#define STRING "example"`, it simply replaces occurrences of `STRING` with `"example"` in your source code during the preprocessing stage.

Example:

```c
#include <stdio.h>

#define STRING "example"

int main() {
    printf("%s\n", STRING);
    return 0;
}
```

The preprocessor replaces `STRING` with `"example"` before the code is compiled:

```c
#include <stdio.h>

int main() {
    printf("%s\n", "example");
    return 0;
}
```

<mark style="color:red;">**Note:**</mark> This is just an example, `"%s\n"` is still a string literal.
