# COM Hijacking



## Introduction

COM (Component Object Model) is a System in Windows to enable communication between software components. References to COM objects are stored in the Registry. Hijacking COM requires us to replace this registry reference with our malicious code.



## Hijacking COM

We want to use COM objects that are not being used by legitimate Software, because it'll break them! The best bet is to find COM objects that are not being used. It's best to do so on our machine first, then on the machine we want to attack.

We can hunt from COM hijacks using [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon). We want to filter by the following:

* _RegOpenKey_ operations.
* where the Result is _NAME NOT FOUND_.
* and the Path ends with _InprocServer32_.
