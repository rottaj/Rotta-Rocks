# Macros

## Introduction

When building PIC, having macros to intrinsic functions is very useful. _Intrinsic_ functions are processed by the compiler itself, and not at runtime. Intrinsic functions will be used instead of CRT-library functions in our case. Microsoft has an [Alphabetical listing of intrinsic functions](https://learn.microsoft.com/en-us/cpp/intrinsics/alphabetical-listing-of-intrinsic-functions?view=msvc-170).

### Memory Manipulation Macros

```c
#define MemCopy         __movsb  // Replacing memcpy
#define MemSet          __stosb  // Replacing memset
#define MemZero( p, l ) __stosb( ( char* ) ( ( PVOID ) p ), 0, l ) // Replacing ZeroMemory   
```

2.Type-Casting Macros: These are macros that are used to type-cast input variables.

```c
#define C_PTR( x )      ( PVOID )     ( x )         // Type-cast to PVOID
#define U_PTR( x )      ( ULONG_PTR ) ( x )         // Type-cast to ULONG_PTR
```
