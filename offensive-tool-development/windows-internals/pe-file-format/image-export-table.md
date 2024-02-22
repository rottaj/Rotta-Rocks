# Image Export Table

## Introduction

The [IMAGE\_EXPORT\_DIRECTORY](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/SystemServices/struct.IMAGE\_EXPORT\_DIRECTORY.html) is not officially documented by Microsoft. Here are some notes from unofficial documentation.

## IMAGE\_EXPORT\_DIRECTORY Structure

The IMAGE\_EXPORT\_DIRECTORY structure is comprised of 3 arrays:

* **AddressOfFunctions**: array containing pointers to exported functions.
* **AddressOfNames**: array containing names of exported functions.&#x20;
* **AddressOfNameOrdinals**: array containing integer ordinal numbers (numeric identifiers) of exported functions. The term "ordinal" is chosen because it implies a specific order or sequence in which functions are listed within the DLL.

The IMAGE\_EXPORT\_DIRECTORY structure also includes the size of the arrays:

* **NumberOfFunctions**: DWORD of number of exported functons.
* **NumberOfNames**: DWORD of number function names.

<mark style="color:yellow;">IMPORTANT:</mark> The ordinal table (AddressOfNameOrdinals) and the name table (AddressOfNames) work in conjunction with each other.&#x20;

From the [official PE-COFF documentation](http://msdn.microsoft.com/en-us/windows/hardware/gg463119.aspx):

> The export name pointer table and the export ordinal table form two parallel arrays that are separated to allow natural field alignment. These two tables, in effect, operate as one table, in which the Export Name Pointer column points to a public (exported) name and the Export Ordinal column gives the corresponding ordinal for that public name.

It is the responsibility of the PE loader to resolve and patch the addresses of the exported functions.

## Reference

{% embed url="https://reverseengineering.stackexchange.com/questions/6652/name-and-ordinal-table-pointers-in-export-directory-are-null-although-dll-export" %}

{% embed url="https://blog.omega-prime.co.uk/2011/07/04/everything-you-never-wanted-to-know-about-dlls/" %}

{% embed url="https://ferreirasc.github.io/PE-Export-Address-Table/" %}
