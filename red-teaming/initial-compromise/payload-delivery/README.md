# Payload Delivery

## Introduction

Once we have access, our immediate next step is to gain persistence. The most optimal, but hardest, is to establish our Command & Control. To do so carries multiple barriers we have to overcome: User privileges, security solutions, firewall rules, etc. All of which means nothing unless our C\&C infrastructure is properly setup to avoid being flagged as suspicious (which will likely happen), or decrypted by Firewall / IDPS / DLP / EDR, amongst others. See above for more.

There are two ways we can deliver this payload after compromising a O365 account:

* Send the payload in a phishing email.
* Send a URL to the victim that contains a download to the payload. (MOTW)
