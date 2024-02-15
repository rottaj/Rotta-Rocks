# Password Protected Files



## .Zip Files

### Zip2john

```bash
┌──(kali㉿kali)-[~/home/kali]
└─$ zip2john sitebackup3.zip >> ziphash.hash
```

### Cracking w/ Hashcat



#### 13600

```bash
┌──(kali㉿kali)-[~/…/Prep/OSCP-A/Crystal/backup]
└─$ hashcat -m 13600 ziphash.hash
hashcat (v6.2.6) starting

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13600 (WinZip)
Hash.Target......: $zip2$*0*1*0*d3da047a75793317*edb3*34e*d7408d919e51.../zip2$
Time.Started.....: Wed Jan  3 14:49:07 2024 (1 sec)
Time.Estimated...: Wed Jan  3 14:49:08 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   224.6 kH/s (7.06ms) @ Accel:512 Loops:999 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 40960/14344385 (0.29%)
Rejected.........: 0/40960 (0.00%)
Restore.Point....: 38912/14344385 (0.27%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-999
Candidate.Engine.: Device Generator
Candidates.#1....: treetree -> loserface1
Hardware.Mon.#1..: Util: 41%

Started: Wed Jan  3 14:49:07 2024
Stopped: Wed Jan  3 14:49:09 2024

```

#### 17200

```
hashcat -m 17200 zipped.hash /usr/share/wordlists/rockyou.txt
```





## PKCS#12 (.p12, .pfx)

PKCS12 is typically used to store private keys. In this example, we'll crack and extract an RC4 encryption key and certificate.

We can use a tool called [crackpkcs12](https://github.com/crackpkcs12/crackpkcs12) to crack a .pfx file

```
$ crackpkcs12 -d /usr/share/wordlists/rockyou.txt ../auth.pfx 

Dictionary attack - Starting 4 threads

*********************************************************
Dictionary attack - Thread 3 - Password found: thuglegacy
*********************************************************

```

### Extract keys

Now with the password, we can extract the encrypted key and certificate. It'll ask to set a PEM password.

```
$openssl pkcs12 -in auth.pfx -nocerts -out auth.key-enc

Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

### Decrypt

The key and certificate we extracted is encrypted. Let's decrypt it.

```
$ openssl rsa -in legacyy_dev_auth.key-enc -out legacyy_dev_auth.key
Enter pass phrase for legacyy_dev_auth.key-enc:
writing RSA key
```

### Dump certificate

<pre><code><strong>$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
</strong>Enter Import Password:
</code></pre>
