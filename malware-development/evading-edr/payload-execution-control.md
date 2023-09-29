---
description: >-
  The more actions malware performs, the more likely it is to be picked up by
  monitoring systems. Limiting the actions performed by malware and focusing on
  essential tasks is called "Execution Control".
---

# Payload Execution Control



## Synchronization Objects

A synchronization object is an object whose handle can be specified in one of the [wait functions](https://learn.microsoft.com/en-us/windows/win32/sync/wait-functions) to coordinate the execution of multiple threads.

The following object types are provided exclusively for synchronization.

| Type           | Description                                                                                                                                                                                                                                                       |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Event          | Notifies one or more waiting threads that an event has occurred. For more information, see [Event Objects](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects).                                                                                   |
| Mutex          | Can be owned by only one thread at a time, enabling threads to coordinate mutually exclusive access to a shared resource. For more information, see [Mutex Objects](https://learn.microsoft.com/en-us/windows/win32/sync/mutex-objects).                          |
| Semaphore      | Maintains a count between zero and some maximum value, limiting the number of threads that are simultaneously accessing a shared resource. For more information, see [Semaphore Objects](https://learn.microsoft.com/en-us/windows/win32/sync/semaphore-objects). |
| Waitable timer | Notifies one or more waiting threads that a specified time has arrived. For more information, see [Waitable Timer Objects](https://learn.microsoft.com/en-us/windows/win32/sync/waitable-timer-objects).                                                          |

&#x20;



## Events

[Event Objects](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects) notify one or more waiting threads that an event has occurred. They can be used to cooridinate the execution of multiple threads or processes. They can be either manual or automatic.

To use events in a program, the [CreateEventA](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa) WinAPI can be employed. The usage of the function is demonstrated below:

```c
HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, "ControlString");

if (hEvent != NULL && GetLastError() == ERROR_ALREADY_EXISTS)
	// Payload is already running
else
	// Payload is not running
```



## Mutex

[Mutex Objects](https://learn.microsoft.com/en-us/windows/win32/sync/mutex-objects) can be owned by only one thread at a time, enabling threads to coordinate mutually exclusive access to a shared resource. Short for "mutual exclusion".

[CreateMutexA](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexa) is used to create a named mutex as follows:

```c
HANDLE hMutex = CreateMutexA(NULL, FALSE, "ControlString");

if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS)
	// Payload is already running
else
	// Payload is not running
```



## Semaphore

[Semaphore Objects](https://learn.microsoft.com/en-us/windows/win32/sync/semaphore-objects) maintain a count between zero and some maximum value, limiting the number of threads that are simultaneously accessing a shared resource. There are two types of semaphores: binary and counting. A binary semaphore has a value of 1 or 0, indicating whether the resource is available or unavailable, respectively. A counting semaphore, on the other hand, has a value greater than 1, representing the number of available resources or the number of processes that can access the resource concurrently.

To control execution of a payload, a named semaphore object will be created each time the payload is executed. If the binary is executed multiple times, the first execution will create the named semaphore and the payload will be executed as intended. On subsequent executions, the semaphore creation will fail as the semaphore with the same name is already running. This indicates that the payload is currently being executed from a previous run and therefore should not be run again to avoid duplication.



[CreateSemaphoreA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createsemaphorea) will be used to create a semaphore object. It is important to create it as a named semaphore to prevent executions after the initial binary run. If the named semaphore is already running, `CreateSemaphoreA` will return a handle to the existing object and `GetLastError` will return `ERROR_ALREADY_EXISTS`. In the code below, if a "ControlString" semaphore is already running, `GetLastError` will return `ERROR_ALREADY_EXISTS`.

```c
HANDLE hSemaphore = CreateSemaphoreA(NULL, 10, 10, "ControlString");

if (hSemaphore != NULL && GetLastError() == ERROR_ALREADY_EXISTS)
	// Payload is already running
else
	// Payload is not running
```

\


## Other Forms of Synchronization Objects

In some circumstances, you can also use a file, named pipe, or communications device as a synchronization object.





### CreateNamedPipeA

Example of setting up a named pipe and using it for inter-process communication (IPC).

Using [CreateNamedPipeA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea):

```c
HANDLE hNamedPipe;
char buffer[1024];
DWORD bytesRead;

// Create a named pipe
hNamedPipe = CreateNamedPipeA(
    "\\\\.\\pipe\\MyNamedPipe",  // Pipe name
    PIPE_ACCESS_DUPLEX,         // Pipe open mode
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, // Pipe mode
    1,                          // Maximum instances
    1024,                       // Output buffer size
    1024,                       // Input buffer size
    0,                          // Default timeout (0 means blocking)
    NULL                        // Security attributes
);

if (hNamedPipe == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "CreateNamedPipe failed with error %d\n", GetLastError());
    return 1;
}

printf("Waiting for a client to connect...\n");

// Wait for a client to connect to the named pipe
if (!ConnectNamedPipe(hNamedPipe, NULL)) {
    fprintf(stderr, "ConnectNamedPipe failed with error %d\n", GetLastError());
    CloseHandle(hNamedPipe);
    return 1;
}

printf("Client connected. Waiting for data...\n");

// Read data from the client
if (ReadFile(hNamedPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
    printf("Received data from client: %s\n", buffer);
} else {
    fprintf(stderr, "ReadFile failed with error %d\n", GetLastError());
}

// Clean up
CloseHandle(hNamedPipe);

return 0;
```



### Others

Taken from microsoft docs:

| Object                       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Change notification          | Created by the [**FindFirstChangeNotification**](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstchangenotificationa) function, its state is set to signaled when a specified type of change occurs within a specified directory or directory tree. For more information, see [Obtaining Directory Change Notifications](https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-directory-change-notifications).                                                                                                                                                                                                                                                                            |
| Console input                | Created when a console is created. The handle to console input is returned by the [**CreateFile**](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) function when CONIN$ is specified, or by the [**GetStdHandle**](https://learn.microsoft.com/en-us/windows/console/getstdhandle) function. Its state is set to signaled when there is unread input in the console's input buffer, and set to nonsignaled when the input buffer is empty. For more information about consoles, see [Character-Mode Applications](https://learn.microsoft.com/en-us/windows/console/character-mode-applications)                                                                                                  |
| Job                          | Created by calling the [**CreateJobObject**](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-createjobobjectw) function. The state of a job object is set to signaled when all its processes are terminated because the specified end-of-job time limit has been exceeded. For more information about job objects, see [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).                                                                                                                                                                                                                                                                                                  |
| Memory resource notification | Created by the [**CreateMemoryResourceNotification**](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-creatememoryresourcenotification) function. Its state is set to signaled when a specified type of change occurs within physical memory. For more information about memory, see [Memory Management](https://learn.microsoft.com/en-us/windows/win32/memory/memory-management).                                                                                                                                                                                                                                                                                                                        |
| Process                      | Created by calling the [**CreateProcess**](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) function. Its state is set to nonsignaled while the process is running, and set to signaled when the process terminates. For more information about processes, see [Processes and Threads](https://learn.microsoft.com/en-us/windows/win32/procthread/processes-and-threads).                                                                                                                                                                                                                                                                                                   |
| Thread                       | Created when a new thread is created by calling the [**CreateProcess**](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa), [**CreateThread**](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread), or [**CreateRemoteThread**](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) function. Its state is set to nonsignaled while the thread is running, and set to signaled when the thread terminates. For more information about threads, see [Processes and Threads](https://learn.microsoft.com/en-us/windows/win32/procthread/processes-and-threads). |

&#x20;

\
