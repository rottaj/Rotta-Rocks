---
description: DNS Recon is an important part of understanding the threat landscape.
---

# DNS Reconnaissance

## Manual Tools

### Basic Testing

```
dig <domain_name> 	Perform a basic forward lookup
nslookup <domain_name> 	As above
host <domain_name> 	As Above
dig @<server> <domain_name> 	Use a specific name server to perform query
nslookup <domain_name> <server> 	As above
dig @<server> version.bind chaos txt 	BIND version details
dig @<server> <domain_name> axfr 	Attempt zone transfer
nslookup
```



## Automated Tools

### DNSRecon

```
└─$ dnsrecon -d megacorpone.com -t std
[*] std: Performing General Enumeration against: megacorpone.com...
[-] DNSSEC is not configured for megacorpone.com
[*]      SOA ns1.megacorpone.com 51.79.37.18
[*]      NS ns3.megacorpone.com 66.70.207.180
[*]      Bind Version for 66.70.207.180 "9.11.5-P4-5.1+deb10u2-Debian"
[*]      NS ns2.megacorpone.com 51.222.39.63
[*]      Bind Version for 51.222.39.63 "9.11.5-P4-5.1+deb10u2-Debian"
[*]      NS ns1.megacorpone.com 51.79.37.18
[*]      Bind Version for 51.79.37.18 "9.11.5-P4-5.1+deb10u2-Debian"
[*]      MX fb.mail.gandi.net 217.70.178.215
[*]      MX fb.mail.gandi.net 217.70.178.217
[*]      MX fb.mail.gandi.net 217.70.178.216
[*]      MX spool.mail.gandi.net 217.70.178.1
[*]      MX mail.megacorpone.com 51.222.169.212
[*]      MX mail2.megacorpone.com 51.222.169.213
[*]      MX fb.mail.gandi.net 2001:4b98:dc4:8::217
[*]      MX fb.mail.gandi.net 2001:4b98:dc4:8::215
[*]      MX fb.mail.gandi.net 2001:4b98:dc4:8::216
[*]      MX spool.mail.gandi.net 2001:4b98:e00::1

```

### DNSEnum

```
└─$ dnsenum siem.megacorpone.com             
dnsenum VERSION:1.2.6

-----   siem.megacorpone.com   -----                                                                                                                 
                                                                                                                                                     
                                                                                                                                                     
Host's addresses:                                                                                                                                    
__________________                                                                                                                                   
                                                                                                                                                     
siem.megacorpone.com.                    5        IN    A        51.222.169.215                                                                      

                                                                                                                                                     
Name Servers:                                                                                                                                        
______________                                                                                                                                       
                                                                                                                                                     
 siem.megacorpone.com NS record query failed: NOERROR         
```
