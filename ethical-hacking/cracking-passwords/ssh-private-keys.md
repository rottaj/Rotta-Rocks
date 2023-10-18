# SSH Private Keys

Often times we'll need to pass in a passphrase along with the SSH private key to gain access to the host via ssh. We can use the private key to try and crack the password.

## Cracking with Hashcat

### Change Permissions of id\_rsa

Chances are we've downloaded a id\_rsa file with read only permissions. To convert to a hash we'll need to update this.

```shell-session
kali@kali$ chmod 600 id_rsa
```

### Convert with ssh2john

```shell-session
kali@kali$ ssh2john id_rsa > id_rsa.hash
```

### Format Hash File

We'll need to fix the hash file output from the JtR suite. Removing the filename before the hash.

We remote **id\_rsa:**

```
id_rsa:$sshng$6$16$705
```

```
$sshng$6$16$705...
```

### Searching For Hash

We can use Hashcat to search for the Hash. We see that it is SHA-512 **22921**

<pre><code>└─$ hashcat -h | grep -i ssh
   6700 | AIX {ssha1}                                                | Operating System
   6400 | AIX {ssha256}                                              | Operating System
   6500 | AIX {ssha512}                                              | Operating System
   1411 | SSHA-256(Base64), LDAP {SSHA256}                           | FTP, HTTP, SMTP, LDAP Server
   1711 | SSHA-512(Base64), LDAP {SSHA512}                           | FTP, HTTP, SMTP, LDAP Server
    111 | nsldaps, SSHA-1(Base64), Netscape LDAP SSHA                | FTP, HTTP, SMTP, LDAP Server
  10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1                        | Enterprise Application Software (EAS)
  22911 | RSA/DSA/EC/OpenSSH Private Keys ($0$)                      | Private Key
  22921 | RSA/DSA/EC/OpenSSH Private Keys <a data-footnote-ref href="#user-content-fn-1">($6$)</a>                      | Private Key
  22931 | RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)                  | Private Key
  22941 | RSA/DSA/EC/OpenSSH Private Keys ($4$)                      | Private Key
  22951 | RSA/DSA/EC/OpenSSH Private Keys ($5$)                      | Private Key
                                                                                            
</code></pre>



### Running Hashcat

```
└─$ hashcat -m 22921 id_rsa.hash passwords.txt                                                                   
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-11th Gen Intel(R) Core(TM) i7-1195G7 @ 2.90GHz, 2910/5884 MB (1024 MB allocatable), 4MCU

This hash-mode is known to emit multiple valid candidates for the same hash.
Use --keep-guessing to continue attack after finding the first crack.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashfile 'id_rsa.hash' on line 1 ($sshng...cfeadfb412288b183df308632$16$486): Token length exception

* Token length exception: 1/1 hashes
  This error happens if the wrong hash type is specified, if the hashes are
  malformed, or if input is otherwise not as expected (for example, if the
  --username option is used but no username is present)

No hashes loaded.

```

#### <mark style="color:red;">If we get No hashes loaded error we'll need to use another tool.</mark>

This is because modern SSH Private keys use AES-256, which Hashcat does not support.



## Cracking with John

### Creating Rules in John

To add rules to John we need to add them to the **/etc/john/john.conf** file**. View "Identifying & Building Rules".**

```shell-session
kali@kali$ cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

kali@kali$ sudo sh -c 'cat rules.txt >> /etc/john/john.conf'
```

### Running John

<pre class="language-shell-session"><code class="lang-shell-session">kali@kali$ john --wordlist=passwords.txt --rules=sshRules id_rsa.hash 
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<a data-footnote-ref href="#user-content-fn-2">Umbrella137!</a>     (?)     
1g 0:00:00:00 DONE (2023-10-18 13:48) 2.040g/s 36.73p/s 36.73c/s 36.73C/s Window137!..Umbrella137#
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

</code></pre>



[^1]: this is it



[^2]: 
