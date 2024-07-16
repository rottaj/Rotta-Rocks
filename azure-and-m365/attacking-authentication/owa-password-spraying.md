# OWA Password Spraying



## Intruduction

We can conduct a password spray attack against Outlook on the web (OWA) using BurpSuite.

OWA has a direct url that generally follows the format: https://\<exchangeserver>/owa

<mark style="color:red;">**Note**</mark>: OWA lockout rules are set to default at 0. Companies generally change this to 8-10 attempts. These rules are configured in GPO, so we won't know the number without access.

