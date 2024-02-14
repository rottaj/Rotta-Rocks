# Creating Shellcode



## Introduction

The easiest way to create complex shellcode is to write everything in C with no external dependencies. We then compile the C code to an object file. Everything must be in the `text` section. Finally, we rip everything out from the `.text` section and that's our shellcode.
