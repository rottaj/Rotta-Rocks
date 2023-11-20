# Identifying & Building Rules

## Hashcat Rules

Hashcat allows us to build rules files to mutate wordlists. Here's how it works:

```
└─$ cat crack.rule    
$1 $@ $3 $$ $5

└─$ cat crack.rule 
u d
```

{% embed url="https://hashcat.net/wiki/doku.php?id=rule_based_attack\" %}

```bash
$ hashcat -m 0 crackme.hash /usr/share/wordlists/rockyou.txt -r demo3.rule --force
```

### Multiple Rules - Same Password

When rule functions are on the same line separated by a space. In this case, Hashcat will use them consecutively on each password of the wordlist.

<pre class="language-shell-session"><code class="lang-shell-session">kali@kali:~/passwordattacks$ cat demo1.rule     
$1 c

<strong>kali@kali:~/passwordattacks$ hashcat -r demo1.rule --stdout demo.txt
</strong>Password1
Iloveyou1
Princess1
Rockyou1
Abc1231
</code></pre>



### Multiple Rules - Separate Passwords

When the rule functions are on separate lines. Hashcat interprets the second rule function, on the second line, as new rule. In this case, each rule is used separately, resulting in two mutated passwords for every password from the wordlist.

```shell-session
kali@kali:~/passwordattacks$ cat demo2.rule   
$1
c

kali@kali:~/passwordattacks$ hashcat -r demo2.rule --stdout demo.txt
password1
Password
iloveyou1
Iloveyou
princess1
Princess
```

