# Creating DLL's

## Introduction

I greatly prefer a UNIX development environment, but sometimes It seems I'm almost forced to develop in Visual Studio (I.E building reflective DLLs). Here are some notes on building DLL's with Visual Studio.&#x20;

## Creating a DLL

To create a DLL in Visual Studio click: Create a Project, set the programming language to C++,  and select Dynamic Link Library (DLL).

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>



### Adding external functions.

To add an external function use the extern keyword

```cpp
extern __declspec(dllexport) BOOL ReflectiveFunction() {
}
```
