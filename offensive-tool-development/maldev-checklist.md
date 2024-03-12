---
description: >-
  This page hopefully serves as an up-to-date checklist of the best TTP's when
  developing evasive offensive tools.
---

# Maldev Checklist

## 2024 Maldev Checklist

### Bypassing AV

* [ ] Native NtAPI wrapping or Indirect Syscalls
* [ ] Payload encryption
* [ ] Brute force decryption key
* [ ] File bloating
* [ ] PE Packing

### Evading EDR & Security Solutions

* [ ] Native NtAPI or Indirect Syscalls
* [ ] Call Stack Spoofing
* [ ] PPID Spoofing
* [ ] Unhooking NTDLL
* [ ] Payload execution control
* [ ] Sleep obfuscation

### IAT Hiding / Obfuscation

* [ ] Custom GetProcAddress, GetModuleHandle with API Hashing.
* [ ] Module stomping.
* [ ] Removing CRT.

### Anti Analysis / Anti VM

* [ ] Self Deletion
* [ ] Delay execution&#x20;
* [ ] Monitoring user behavior (mouse clicks)



## Additional Tools

* [ ] [Loldrivers](https://www.loldrivers.io/)
