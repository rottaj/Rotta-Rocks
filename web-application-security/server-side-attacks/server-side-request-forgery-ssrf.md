---
description: >-
  Server-Side Request Forgery (SSRF) is making the hosting application server
  issue requests to an arbitrary, external or internal, resource in an attempt
  to identify sensitive data.
---

# Server-Side Request Forgery (SSRF)

_**Exploiting SSRF vulnerabilities can lead to:**_

* Interacting with known internal systems.
* Discovering internal services via port scans.
* Disclosing local/sensitive data.
* Including files in the target application.
* Leaking NetNTLM hases using UNC Paths (Windows).
* Achieving remote code execution.



**When hunting for SSRF we should look for the following:**

* Parts of HTTP requests, including URLS.
* File imports such as HTML, PDFs, images, etc.
* Remote server connections to fetch data.
* API specification imports.
* Dashboards including ping and similar functionalities to check server statuses.



<mark style="color:red;">**NOTE:**</mark>** When fuzzing web applications, fuzzing should not just be limited to input fields only. Extend fuzzing to parts of the HTTP request as well, such as **_**User-Agent.**_



### Interacting with the Target:

_**Accessing local resources:**_

```bash
curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=index.html"
```

```bash
curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:1"
```

_**Port Fuzzing:**_

```bash
ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT" -fr 'Errno[[:blank:]]111'
```

_**Interacting with internal resource on a discovered port:**_

```bash
curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:5000" 	
```

_**Retrieving Local File:**_

```bash
 curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///app/internal_local.py"
```





## Blind SSRF:

Blind SSRF occurs when the request if processed yet we can't see the backend server's response.

To detect if a backend service is processing our requests, we can use a public IP address taht we own or services such as:

* Burp Collaborator - [https://portswigger.net/burp/documentation/collaborator](https://portswigger.net/burp/documentation/collaborator)
* [http://pingb.in](http://pingb.in)

<mark style="color:red;">**NOTE:**</mark> Blind SSRF vulnerabilites could exist in PDF Document generators and HTTP Headers, among other locations.





## Bypassing SSRF Defenses

It is common to see applications containing SSRF behavior together with defenses aimed at preventing malicious exploitation.&#x20;



### SSRF with Blacklist-based Input Filters

Some applications block input containing hostnames like _127.0.0.1_ and _localhost_, or sensitive URLS like _/admin_.

We may be able to circumvent the filter using various techniques:

* <mark style="color:green;">**TRY:**</mark> Using an alternative IP representation of `127.0.0.1`, such as `2130706433`, `017700000001`, or `127.1`.
* Registering your own domain name that resolves to `127.0.0.1`. You can use a vps or burp collaborator for this purpose.
* <mark style="color:green;">**TRY:**</mark> Obfuscating blocked strings using URL encoding or case variation.
* Providing a URL that you control, which subsequently redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an `http:` to `https:` URL during the redirect has been shown to bypass some anti-SSRF filters.

_**Tools:**_

_**IPFuscator:**_ [https://github.com/vysecurity/IPFuscator](https://github.com/vysecurity/IPFuscator)



### SSRF with Whitelist-based Input Filters

Some applications only allow input that matches, beings with, or contains, a whitelist of permitted values. This is generally the most secure, but we can sometimes circumvent the filter.

*   You can embed credentials in a URL before the hostname, using the `@` character. For example:

    `https://expected-host:fakepassword@evil-host`
*   You can use the `#` character to indicate a URL fragment. For example:

    `https://evil-host#expected-host`
*   You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example:

    `https://expected-host.evil-host`
* You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request. Note that you can also try [double-encoding](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings#obfuscation-via-double-url-encoding) characters; some servers recursively URL-decode the input they receive, which can lead to further discrepancies.
* You can use combinations of these techniques together.



### Bypassing SSRF filters via open redirection

It is sometimes possible to bypass any kind of filter-based defenses by exploiting an open redirection vulnerability.&#x20;

For example, suppose an application contains an open redirection vulnerability in which the following URL:&#x20;

`/product/nextProduct?currentProductId=6&path=http://evil-user.net`

returns a redirection to:

`http://evil-user.net`

We can leverage the open redirection vulnerability to bypass the URL filter, and exploit the SSRF vulnerability as follows:

`POST /product/stock HTTP/1.0 Content-Type: application/x-www-form-urlencoded Content-Length: 118 stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin`

This exploit works because the application first validates that the supplied URL is on an allowed domain, which it is. The application then requests the supplied URL, which triggers the open redirection. It follows the redirection, and makes a request to the internal URL of the attackers choosing.
