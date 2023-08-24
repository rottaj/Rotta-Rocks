# DNS Reconnaissance

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

