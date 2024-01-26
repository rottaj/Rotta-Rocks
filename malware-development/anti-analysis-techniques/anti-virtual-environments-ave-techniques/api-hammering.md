# API Hammering

## Introduction

API Hammering is a sandbox bypass technique in which random WinAPI functions are called in order to delay the execution of a program.

### Example Functions to Utilize

API Hammering can utilize any WINAPI functions, it's important to get creative and not use ones that are commonly used. In this page, we will go over some common ones to set the stage.

* [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) - Used to create and open a file.
* [WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile) - Used to write data to a file.
* [ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile) - Used to read data from a file.

<mark style="color:yellow;">**We want WinAPI function that have the ability to consume considerable processing time.**</mark>

## API Hammering Methodology

API Hammering gives us the ability to get creative, in this method, we'll create a file, write large amounts of data to it, and then read the file into a buffer. When the file is reopened, it is marked for deletion when the handle is closed.

The only parameter the function requires is `dwStress` which is the number of times to repeat the entire process.

<mark style="color:yellow;">**The function will continue opening, writing, reading, and deleting the file until dwStress is complete.**</mark>

We will create a temorary .tmp file in the `C:\Users\User\AppData\Local\Temp` folder. We will use  [GetTempPathW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettemppathw) WinAPI function which is used to retrieve the path of the temp directory.

{% code fullWidth="true" %}
```c

// File name to be created
#define TMPFILE	L"Malware.tmp"

BOOL ApiHammering(DWORD dwStress) {

	WCHAR     szPath                  [MAX_PATH * 2],
              szTmpPath               [MAX_PATH];
	HANDLE    hRFile                  = INVALID_HANDLE_VALUE,
              hWFile                  = INVALID_HANDLE_VALUE;
	
	DWORD   dwNumberOfBytesRead       = NULL,
            dwNumberOfBytesWritten    = NULL;
	
	PBYTE   pRandBuffer               = NULL;
	SIZE_T  sBufferSize               = 0xFFFFF;	// 1048575 byte
	
	INT     Random                    = 0;

	// Getting the tmp folder path
	if (!GetTempPathW(MAX_PATH, szTmpPath)) {
		printf("[!] GetTempPathW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Constructing the file path 
	wsprintfW(szPath, L"%s%s", szTmpPath, TMPFILE);

	for (SIZE_T i = 0; i < dwStress; i++){

		// Creating the file in write mode
		if ((hWFile = CreateFileW(szPath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL)) == INVALID_HANDLE_VALUE) {
			printf("[!] CreateFileW Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		// Allocating a buffer and filling it with a random value
		pRandBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBufferSize);
        srand(time(NULL));
		Random = rand() % 0xFF;
		memset(pRandBuffer, Random, sBufferSize);

		// Writing the random data into the file
		if (!WriteFile(hWFile, pRandBuffer, sBufferSize, &dwNumberOfBytesWritten, NULL) || dwNumberOfBytesWritten != sBufferSize) {
			printf("[!] WriteFile Failed With Error : %d \n", GetLastError());
			printf("[i] Written %d Bytes of %d \n", dwNumberOfBytesWritten, sBufferSize);
			return FALSE;
		}

		// Clearing the buffer & closing the handle of the file
		RtlZeroMemory(pRandBuffer, sBufferSize);
		CloseHandle(hWFile);

		// Opening the file in read mode & delete when closed
		if ((hRFile = CreateFileW(szPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
			printf("[!] CreateFileW Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		// Reading the random data written before 	
		if (!ReadFile(hRFile, pRandBuffer, sBufferSize, &dwNumberOfBytesRead, NULL) || dwNumberOfBytesRead != sBufferSize) {
			printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
			printf("[i] Read %d Bytes of %d \n", dwNumberOfBytesRead, sBufferSize);
			return FALSE;
		}

		// Clearing the buffer & freeing it
		RtlZeroMemory(pRandBuffer, sBufferSize);
		HeapFree(GetProcessHeap(), NULL, pRandBuffer);

		// Closing the handle of the file - deleting it
		CloseHandle(hRFile);
	}


	return TRUE;
}

```
{% endcode %}



## Delay Execution

To properly delay the execution, calculate how many cycles is sufficient with `GetTickCount64` to measure the time before and after the ApiHammering function is called.

```c
int main() {

	DWORD	T0	= NULL,
            T1	= NULL;

	T0 = GetTickCount64();

	if (!ApiHammering(1000)) {
		return -1;
	}

	T1 = GetTickCount64();

	printf(">>> ApiHammering(1000) Took : %d MilliSeconds To Complete \n", (DWORD)(T1 - T0));

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
```

**Convert Seconds To Cycles**

The `SECTOSTRESS` macro below can be used to convert the number of seconds, `i`, to the number of cycles. Since 1000 loop cycles took 5.157 seconds, each one second will take 1000 / 5.157 = 194. The output of the macro should be used as a parameter for the `ApiHammering` function.

```c
#define SECTOSTRESS(i)( (int)i * 194 )
```

### D**elaying Execution Via API Hammering Code**

The code snippet below shows the main function using the previously mentioned technique.

```c
int main() {


  DWORD T0  = NULL,
        T1  = NULL;

  T0 = GetTickCount64();

  // Delay execution for '5' seconds worth of cycles
  if (!ApiHammering(SECTOSTRESS(5))) {
    return -1;
  }

  T1 = GetTickCount64();

  printf(">>> ApiHammering Delayed Execution For : %d \n", (DWORD)(T1 - T0));

  printf("[#] Press <Enter> To Quit ... ");
  getchar();

  return 0;
}

```

## API Hammering in a Thread

The ApiHammering function we created can be executed in a thread that runs in the background until the end of the main threads execution.

The main function shown below creates a new thread and calls the `ApiHammering` function with a value of `-1`.

```c
int main() {

	DWORD dwThreadId = NULL;


	if (!CreateThread(NULL, NULL, ApiHammering, -1, NULL, &dwThreadId)) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return -1;
	}

	printf("[+] Thread %d Was Created To Run ApiHammering In The Background\n", dwThreadId);


	/*
	
		injection code can be here

	*/


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
```

Passing **`-1`** as a value makes the thread loop over the process infinitely it will die when the main thread is finished executing.
