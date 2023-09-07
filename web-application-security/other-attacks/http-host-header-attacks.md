---
description: Examples / Cheatsheet for Testing HTTP Host Header Vulnerabilities
---

# HTTP Host Header Attacks

_<mark style="color:red;">**NOTE:**</mark>** To test for HTTP Host Header vulnerabilities, you'll need an intercepting proxy, and manual testing Repeater & Intruder.**_&#x20;

_**In short, we need to identify whether we are able to modify the Host header and still reach the target application with our request.**_

_<mark style="color:red;">**IMPORTANT:**</mark>** ****When probing for HTTP Host header vulnerabilities we often come across behavior that looks vulnerable but isn't exploitable. For example, seeing a host header reflected on markup, or used directly in script imports... There is no way for an attacker to force a victim's browser to issue an incorrect host in any useful manner. (Unless there is some type of cache mechanism)**_

### Supply an arbitrary Host header

The first step is to see what happens when we supply an arbitrary, unrecognized domain name via the Host header.

### Inject Duplicate Host Headers

```http
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: bad-stuff-here
```

### Supply absolute URL

```http
GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-stuff-here
```

### Add line wrapping

```http
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-website.com
```

### Check for flawed validation

Instead of receiving an "Invalid Host header" we might find that our request is blocked as some kind of security measure. We may be able to reveal a loophole around these.

Try to understand how the website parses the Host header.

```http
GET /example HTTP/1.1
Host: vulnerable-website.com:bad-stuff-here
```

Other sites will try to apply matching logic to allow for arbitrary subdomains. In this case, you may be able to bypass the validation entirely by registering an arbitrary domain name that ends with the same sequence of characters as a whitelisted one:

```http
GET /example HTTP/1.1 Host: notvulnerable-website.com
```

Alternatively, you could take advantage of a less-secure subdomain that you have already compromised:

```http
GET /example HTTP/1.1 
Host: hacked-subdomain.vulnerable-website.com
```
