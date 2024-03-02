# wininet.h



## Introduction

The Microsoft Windows Internet (WinINet) API enables applications to access standard Internet protocols, such as FTP and HTTP.

To use wininet we must link it

```c
#pragma comment (lib, "wininet.lib")
```

## HTTP Request

The flow for creating a web request with wininet is as follows:

* `InternetOpen`: Opens a root HINTERNET handle. (Used to enable connection to internet).
* `InternetOpenUrlW`: Opens a resource specified by URL.&#x20;
* `HttpOpenRequestW`
* `HttpSendRequestW`
