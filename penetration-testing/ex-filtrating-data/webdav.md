---
description: >-
  Say we have access to a RDP and want to exfiltrate data via a GUI. WebDAV is a
  quick and useful tool to do so.
---

# WebDAV

## Start WebDAV Server

We will start a webDAV server on our Kali host

```
┌──(env)─(kali㉿kali)-[~]
└─$ /home/kali/env/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/web/
Running without configuration file.
19:23:48.192 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
19:23:48.193 - INFO    : WsgiDAV/4.3.0 Python/3.11.6 Linux-6.3.0-kali1-amd64-x86_64-with-glibc2.37
19:23:48.193 - INFO    : Lock manager:      LockManager(LockStorageDict)
19:23:48.193 - INFO    : Property manager:  None
19:23:48.193 - INFO    : Domain controller: SimpleDomainController()
19:23:48.193 - INFO    : Registered DAV providers by route:
19:23:48.193 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/home/kali/env/lib/python3.11/site-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)

```



## Navigate with Windows Explorer

We can type in the URL of our WebDAV server.

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>
