# File Bloating



## Introduction

File bloating works by filling an executable with junk data, typically null bytes. This works because some security solutions (primarily host based) limit the file size their scanning to avoid consuming too much resources.



## From Linux

```bash
# Make a copy
cp evil.exe evil-200mb.exe

# Add 200mb null bytes to the end of the file
dd if=/dev/zero bs=1M count=200 >> evil-200mb.exe
```



## Visual Studio Creating Large Metadata

1. Create a large file of random data of `FF` bytes using `dd if=/dev/zero bs=1M count=200 | tr '\000' '\377' > file.bin`.
2. Create a `.rc` file in the Visual Studio project.&#x20;
3. Add `IDR_BINARY_FILE BINARY bloat.bin` to the `.rc` file.
4. Compile the solution.

This will create a large file that includes `bloat.bin` within the binary.
