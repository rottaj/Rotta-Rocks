---
description: >-
  In the context of Maldev, API hooking can be used for various purposes,
  including bypassing AV, evading EDR, and anti-debugging. API hooking can be a
  powerful technique when developing malware.
---

# API Hooking

_<mark style="color:red;">**NOTE:**</mark>_ It's important to note that modern security tools have evolved to detect such techniques. Behavior-based analysis, heurisitics, and machine learning are some methods security solutions deploy to detect and respond to threats. The effectiveness of using API hooking for bypassing AV & evading EDR depends on the sophistication of the malware.

***

## Why API Hook?

* Gather sensitive information or data.
* Intercept functions for malicious purpose.
* Bypass security measures.
* Hack games.
* Debugging / Anti-debugging.

## Detour Hooking (Trampoline hooking)

Detour hooking, also known as trampoline hooking, involves redirecting API calls to a detour function or a trampoline function.&#x20;

_**How it works:**_

This is done by overwriting the beginning of the API function with a jump instruction that redirects execution to a trampoline function.

The trampoline function contains the original code of the API that we are hooking as well as our additional code.&#x20;

Finally, execution control is returned to the caller of the API.

## Inline Hooking

Inline hooking, also known as code hooking or function hooking, involves modifying the target API call directly within the original function's code. Instead of redirecting execution to a separate function. The modifications are made inline.

_**How it works:**_

Locate the API call: The hooking process identifies the location within the target binary where the call is being made

Modify the code: The code at the location is modified to include our custom functionality

Finally, execution control is returned.



