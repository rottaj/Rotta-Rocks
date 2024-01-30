---
description: >-
  Server-Side Template Injection (SSTI) is when an attacker injects malicious
  template directives inside a template.
---

# Server-Side Template Injection (SSTI)



### SSTI Identification:

The diagram below can help us identify if we are dealing with an SSTI vulnerability and also identify the underlying template engine.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

In addition to the above diagram, we can try the following approaches to recognize the technology we are dealing with:

* Check verbose errors for technology names. Sometimes just copying the error in Google search can provide us with a straight answer regarding the underlying technology used
* Check for extensions. For example, .jsp extensions are associated with Java. When dealing with Java, we may be facing an expression language/OGNL injection vulnerability instead of traditional SSTI
* Send expressions with unclosed curly brackets to see if verbose errors are generated. Do not try this approach on production systems, as you may crash the webserver.



_**The following payload from CobaltStrike is a popular identifier of SSTI:**_

```
${{<%[%'"}}%\.
```

_**More payloads:**_

```
 *{7*7}
 ${7*7}
 ${{7*7}}
 #{7*7}
 <%= 7*7 %>
```

<mark style="color:red;">**NOTE:**</mark> When searching for SSTI don't forget to include URLS.

```
curl -gs "http://<TARGET IP>:<PORT>/execute?cmd={{7*'7'}}"
```
