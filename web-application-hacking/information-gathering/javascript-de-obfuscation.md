---
description: Here are some useful tools to De-obfuscate javascript
---

# JavaScript De-obfuscation

{% embed url="https://jsconsole.com/" %}

{% embed url="https://prettier.io/playground/" %}

{% embed url="https://beautifier.io/" %}

{% embed url="http://www.jsnice.org/" %}

| `curl http:/SERVER_IP:PORT/`                               | cURL GET request            |
| ---------------------------------------------------------- | --------------------------- |
| `curl -s http:/SERVER_IP:PORT/ -X POST`                    | cURL POST request           |
| `curl -s http:/SERVER_IP:PORT/ -X POST -d "param1=sample"` | cURL POST request with data |
| `echo hackthebox \| base64`                                | base64 encode               |
| `echo ENCODED_B64 \| base64 -d`                            | base64 decode               |
| `echo hackthebox \| xxd -p`                                | hex encode                  |
| `echo ENCODED_HEX \| xxd -p -r`                            | hex decode                  |
| `echo hackthebox \| tr 'A-Za-z' 'N-ZA-Mn-za-m'`            | rot13 encode                |
| `echo ENCODED_ROT13 \| tr 'A-Za-z' 'N-ZA-Mn-za-m'`         | rot13 decode                |
