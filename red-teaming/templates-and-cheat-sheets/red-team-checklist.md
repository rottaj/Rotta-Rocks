# Red Team Checklist







### Phishing Infrastructure





## External Reconnaissance / Enumeration

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

### Password Spraying

Far from the best method of gaining access these days. All eyes are you from the SOC when performing these attacks. That said, password spraying incidents cause massive bloat in alerts for blue team. Some orgs may decide to exclude this activity entirely as they have measures in place to mitigate activity. Account lockouts, Conditional Access Policy (CAP), etc.

#### Generate Wordlist

There are many wordlist generators out there for usernames. Will not name them.

* <pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ~/namemash.py names.txt > possible.txt
  </strong></code></pre>





&#x20;

*



