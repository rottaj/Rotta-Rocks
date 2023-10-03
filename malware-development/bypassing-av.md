---
description: >-
  At its core, a modern AV is fueled by signature updates fetched from the
  vendors signature database. Those signature definitions are stored in the AV's
  local database.
---

# Bypassing AV



## Anti Virus Components

A modern antivirus is typically designed around the following components:

* `File Engine`: Responsible for both scheduled and real-time file scans. Parses the entire file system and sends each file's metadata or data to the signature engine
* `Memory Engine`: Inspects each process's memory space at runtime for well-known binary signatures or suspicious API calls
* `Network Engine`: Inspects the incoming and outgoing network traffic on the local network interface. If a signature is matched, it might attempt to block that connection.
* `Emulator/Sandbox:` Loads files into sandbox, closes environment that emulates execution. This can counteract malware encryption / obfuscation.
* `Disassembler`: Responsible for translating machine code into assembly language, reconstructing the original program code section, and identifying any encoding/decoding routine.
* `Browser Plugin`: Modern AVs often employ browser plugins to get better visibility and detect malicious content that might be executed inside the browser. Protected by Sandbox.
* `Machine Learning Engine`: A vital part of current AVs as it enables detection of unknown threats by relying on cloud-enhanced computing resources and algorithms.



## Detection Methods

Modern antivirus use the following methods:

* `Signature-based Detection`: Filesystem is scanned for known malware signatures and if any are detected, the offending files are quarantined.
* `Heuristic-based Detection`: Relies on various rules and algorithms to determine whether or not an action is considered malicious. Searches for various patterns and program calls that may be considered suspicious.
* `Behavioral Detection`: Searching for behaviors or actions that are considered malicious. Often times by emulating in a small virtual machine / sandbox environment.
* `Machine Learning Detection`: Uses machine learning algorithms and models to collect additional data on behavior or program.

_<mark style="color:red;">**NOTE:**</mark>_ Microsoft Windows Defender has two ML components: the client ML engine, which is responsible for creating ML models and heuristics, and the cloud ML engine, which is capable of analyzing the submitted sample against a metadata-based model comprised of all the submitted samples





## Bypassing AV

To have highly effective antivirus evasion requires _anti-reversing_, _anti-debugging_, _virtual machine emulation detection, direct / indirect use of syscalls, IAT hiding & obfuscation, packing & crypting._



_**Reference:**_

Packers:

{% embed url="https://upx.github.io/" %}
