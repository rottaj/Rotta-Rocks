---
description: >-
  Username enumeration is frequently overlooked, probably because it is assumed
  that a username is not private information.
---

# Username Brute Forcing

_**SecLists**_ provides an extensive collection of wordlists that can be used as a starting point to mount user enumeration attacks: [https://github.com/danielmiessler/SecLists/tree/master/Usernames](https://github.com/danielmiessler/SecLists/tree/master/Usernames)



_**Enumerate through Registration Form:**_

If the registration form prompts the user that the username is already taken, this can be used to enumerate known user accounts.

_**Predictable Usernames:**_

In web applications with fewer UX requirements like, for example, home banking or when there is the need to create many users in a batch, we may see usernames created sequentially.

While uncommon, you may run into accounts like `user1000`, `user1001`. It is also possible that "administrative" users have a predictable naming convention, like `support.it`, `support.fr`, or similar. An attacker could infer the algorithm used to create users (incremental four digits, country code, etc.) and guess existing user accounts starting from some known ones.





### Fuzzing Examples:

_**GET**_ - Fuzzing for User

```bash
wfuzz -z file,/path/to/wordlist.txt -u http://127.0.0.1:80/site/FUZZ
```

_**POST**_ - Fuzzing for User

```
wfuzz -z file,/path/to/user.txt -z file,/path/to/pass.txt http://127.0.0.1/login.php -d "user=FUZZ&pass=FUZ2Z"
```
