---
description: >-
  Similar to the previous section, web applications may have a whitelist of
  allowed extensions. A whitelist is generally more secure than a blacklist.
---

# Whitelist Filters

### Double Extensions

A possible bypass to Whitelist Filters is to test through Double Extensions. For example, if the .jpg extensions is allowed, we can add to our uploaded file at the end. -> <mark style="color:green;">**shell.jpg.php.**</mark>



### Reverse Double Extensions

In some cases, the file upload itself may not be vulnerable, but the web server configuration may lead to a vulnerability and may allow the execution of code from a file like -> <mark style="color:green;">**shell.php.jpg**</mark>



### Obfuscating / Character Injection

When testing for file upload vulnerabilities it's imperative to test with special characters. Each of these characters has a special use case and is worth testing for:

* `%20`
* `%0a`
* `%00`
* `%0d0a`
* `/`
* `.\`
* `.`
* `…`
* `:`

_<mark style="color:green;">**READ:**</mark>_ For example, (shell.php%00.jpg) works with PHP servers with version 5.X and earlier, as it causes the PHP web server to end the file name after the %00 and store it as shell.php.

The same can word for Windows Server by injecting a colon (:) before the allowed file extension (e.g. shell.aspx;.jpg), which should also write the file (shell.aspx).

_<mark style="color:red;">**NOTE:**</mark>_ This is just a small selection of the many ways it's possible to obfuscate file extensions.
