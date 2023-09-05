---
description: >-
  DOM-based XSS arise when JavaScript takes data from an attacker-controllable
  source, like a URL, and passes it to sink that supports code execution. Such
  as eval(), or innerHTML.
---

# DOM-based XSS

_<mark style="color:red;">**NOTE:**</mark>_ The most common source for DOM-based XSS is the URL, which is typically access with window.location.



The document.write sink works with script elements.

```
document.write('<script>alert(document.domain)</script>');
```

### Sinks that can lead to DOM-XSS Vulnerabilities

The following are some of the main sinks that can lead to DOM-XSS vulnerabilities:

```
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
```

The following jQuery functions are also sinks that can lead to DOM-XSS vulnerabilities:

```
add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```
