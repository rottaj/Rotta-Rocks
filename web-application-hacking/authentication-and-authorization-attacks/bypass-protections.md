---
description: Web Applications deploy various protections to prevent brute forcing attacks.
---

# Bypass Protections

### Circumventing IP Restrictions

Some website may block your IP address if they feel you've been attempting to brute force their application. One way we can circumvent this is with the _**X-Forwarded-For**_ HTTP Header.

Other protections might block an IP if you fail to log in too many times. In some implementations, the attacker simply has to log in to their own account every few attempts to prevent this.



#### User rate limiting <a href="#user-rate-limiting" id="user-rate-limiting"></a>

Another way websites try to prevent brute-force attacks is through user rate limiting. In this case, making too many login requests within a short period of time causes your IP address to be blocked. Typically, the IP can only be unblocked in one of the following ways:

* Automatically after a certain period of time has elapsed
* Manually by an administrator
* Manually by the user after successfully completing a CAPTCHA

User rate limiting is sometimes preferred to account locking due to being less prone to username enumeration and denial of service attacks. However, it is still not completely secure. As we saw an example of in an earlier lab, there are several ways an attacker can manipulate their apparent IP in order to bypass the block.

As the limit is based on the rate of HTTP requests sent from the user's IP address, it is sometimes also possible to bypass this defense if you can work out how to guess multiple passwords with a single request.



## Bypass Insecure Authentication

Below we have a authentication scheme in php that uses strcmp to compare strings.

<figure><img src="../../.gitbook/assets/image (6) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

This can be bypass in burp by:

<figure><img src="../../.gitbook/assets/image (7) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
