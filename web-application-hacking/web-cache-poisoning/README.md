---
description: >-
  Web Cache Poisoning is a technique whereby an attacker exploits the behaviour
  of a web server and cache to serve malicious HTTP responses to other users.
---

# Web Cache Poisoning

## Web Cache Poisoning works in two stages

### Stage 1:

The attacker works out a way to elicit a response from the back-end server that contains a dangerous payload

### Stage 2:

The attacker makes sure the response is cached and subsequently served to the intended victim. (Or themselves)\\

## Identify and evaluate unkeyed inputs

_<mark style="color:red;">**NOTE:**</mark>_ Cache keys usually contain the request line and _**Host**_ header. Components of the request that are not included in the cache key are said to be "unkeyed"

_**Any web cache poisoning attack relies on manipulation of unkeyed inputs, such as headers.**_



The first step when constructing a web cache poisoning attack is identify unkeyed inputs. **We can identify unkeyed inputs manually by adding random inputs to requests and observing whether or not they have an effect on the response.**

<mark style="color:red;">**FUZZ FUZZ FUZZ FUZZ**</mark>

1. **Cookie Header**
2. **Authorization Header**
3. **User-Agent Header**
4. **Referer Header**
5. **Accept-Encoding Header**
6. **Range Header**
7. **If-None-Match Header**
8. **If-Match Header**
9. **If-Modified-Since Header**
10. **If-Unmodified-Since Header**
11. **Connection Header**
12. **Pragma Header**
13. **X-Forwarded-Host Header**
14. **X-Forwarded-For Header**
15. **Accept-Language Header**
16. **X-Requested-With Header**
17. **DNT (Do Not Track) Header**
18. **X-Frame-Options Header**

**Param Miner**

We can automate the process with Burp Suites "Param Miner" extension on the BApp store.

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-06 075053.png" alt=""><figcaption></figcaption></figure>

**To use param miner, right-click on a request you want to investigate and click "Guess headers".**

**The output is stored in: Extensions > Installed > Output**

**Caution:** When testing for unkeyed inputs on a live website, there is a risk of inadvertently causing the cache to serve your generated responses to real users. Therefore, it is important to make sure that your requests all have a unique cache key so that they will only be served to you.



_<mark style="color:red;">**NOTE:**</mark>_ Whether or not a response gets cached can depend on all kinds of factors, such as the file extension, content type, route, status code, and response headers. You will probably need to devote some time to simply playing around with requests on different pages and studying how the cache behaves.
