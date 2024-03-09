---
description: >-
  Web servers may keep a list of prohibited File Extensions, MIME-Types,
  Content-Types, and any other security related filters that could be harmful to
  the application.
---

# Blacklist Filters

_**This practice is inherently flawed as it's difficult to explicitly block every possible file extenson that could be used to execute code.**_

Such blacklists can sometimes be bypassed by using lesser known, alternative file extensions that may still be executable, such as `.php5`, `.shtml`, and so on.

### Fuzzing Extensions

We can use PayloadAllTheThings list of extensions to fuzz the application for file extensions that bay not be blacklisted.

_**Web Extensions**_ - [https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)

_**PHP**_ - [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)

_**.NET**_ - [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP)



We can use Burpsuite Intruder to add the extension wordlist and fuzz the application.



