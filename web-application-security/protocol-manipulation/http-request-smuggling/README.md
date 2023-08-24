# HTTP Request Smuggling

In modern web applications, users send requests to a front-end server (load balancer or reverse proxy) and this server forwards requests to one or more back-end servers. This architecture is incredibly common and sometimes unavoidable in cloud based applications.



When a front-end server forwards HTTP requests to a back-end server, it sends several requests over the same back-end network connection for optimal efficiency and performance.&#x20;

Here's how it works:

_**HTTP requests are sent after one another, and the receiving server parses the request headers to determine where one request ends and the next begins.**_

It is crucial that both systems agree on the boundaries between each request. Otherwise an attacker can send an ambiguous request that gets interpreted differently, and can have devastating results.

<figure><img src="../../../.gitbook/assets/Screenshot 2023-08-24 095346.png" alt=""><figcaption><p>Attacker smuggles HTTP request</p></figcaption></figure>







## How HTTP request smuggling arises

Most HTTP request smuggling vulnerabilties occur because the HTTP specification provides two different ways to specify where a request ends:

The _**Content-Length**_ and _**Transfer-Encoding**_ headers.



Content-Type specifies the length of the body in bytes:

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

Transfer-Encoding specifies that the body uses chunked encoding (one or more chunks of data). Each chunk includes a chunk size in bytes(hexadecimal), followed by a newline, followed by the chunk contents. _**The message is terminated with a chunk size of 0.**_

```
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```





## Introduction to Vulnerability

_<mark style="color:red;">**NOTE:**</mark>_ Since the HTTP specification provides two different methods to determine the length of HTTP messages, it is possible for a single message to use both methods at once, so that they conflict each other.

The HTTP specification attempts to prevent this problem by stating that if both the Content-Length and Transfer-Encoding are present, then the Content-Length is ignored.

_**This security feature may be sufficient when only a single server is in play, but problems can arise when two or more servers are chained together.**_

_**Problems arise for two reasons:**_

* Some servers do not support the `Transfer-Encoding` header in requests.
* Some servers that do support the `Transfer-Encoding` header can be induced not to process it if the header is obfuscated in some way.

If the front-end and back-end servers behave differently in relation to the _**Transer-Encoding**_ header, they might disagree on the boundaries between requests. Leading to request smuggling.

_<mark style="color:red;">**NOTE:**</mark>_&#x20;

Many security testers are unaware that chunked encoding can be used in HTTP requests, for two reasons:

* Burp Suite automatically unpacks chunked encoding to make messages easier to view and edit.
* Browsers do not normally use chunked encoding in requests, and it is normally seen only in server responses.

