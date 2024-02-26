# Processes & PEB Structure

## Introduction

In short, a process is an instance of an executing program. It consists of various resources such as threads, handles, memory, and security contexts.

A process in Windows includes:

* **A Unique Process ID (PID)**
* **Virtual Address Space (VAS)**: Every process is allocated it's own Virtual Address Space. This VAS is compartmentalized into PE sections (code, data, stack).
* **Executable Code (PE Image)**: The image of the file stored on disk.
* **Handle Table**: Holds the handles that are opened.&#x20;
* **Access Tokens (Security Context)**: Access tokens encapsulate information about the processes security privileges. Includes the user account and it's access rights.
* **Threads**: Processes run atlest 1 or more threads. Threads enable concurrent execution.

