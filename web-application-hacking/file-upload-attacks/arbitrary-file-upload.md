---
description: >-
  In the wild, it's unlikely we'll find a website that has no protection against
  file upload attacks. But just because defenses are in place, doesn't mean
  their robust.
---

# Arbitrary File Upload

### Quick Notes

Web server directories are typically configured in a way that user-uploaded files will likely have much stricter controls (non-executable) than other locations on the file system that are assumed to be out of reach for end users.&#x20;

If you can find a way to upload a script to a different directory that's not supposed to contain user-supplied files, the server may execute your script.



<mark style="color:red;">**Note:**</mark> When interacting with a web application, it's incredibly likely that our requests will be sent to a reverse proxy of some kind or additional servers behind the scenes.



### Identifying Web Framework

In order to upload a malicious file to the web server, we need to identify the underlying technology it's using. In many cases, we'll be uploading a web shell, or a reverse shell script through the vulnerable file upload. In order for this to sucessfully execute, we need to insure the script is written in the same language the web server is written in.



_**List of Web Shells:**_

_**SecLists -**_ [_**https://github.com/danielmiessler/SecLists/tree/master/Web-Shells**_](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells)

_**RevShells -**_ [_**https://www.revshells.com/**_](https://www.revshells.com/)
