# Installing Windows SDK & WDK



## Visual Studio Installation

Here you can install Windows SDK and WDK

{% embed url="https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk" %}

## Mingw Installation

{% embed url="https://winlibs.com/#download-release" %}

We can include the directory in our CMakeLists.txt:

`include_directories("C:\mingw64\x86_64-w64-mingw32\include\ddk\")`

