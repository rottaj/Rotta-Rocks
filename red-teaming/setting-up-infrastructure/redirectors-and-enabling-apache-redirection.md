# Redirectors & Enabling Apache Redirection

## Redirectors

It's important to never store any data on a redirector, traffic should only transmit through it.&#x20;

* We can setup an SSH or VPN tunnel from the C2 server to the HTTP redirector. We want it done this way so no sensitive private keys or credentials for the C2 server on our redirector.



## Install Apache



## Setup SSH Reverse Tunnel

We need to create a reverse SSH tunnel from our team server to our redirectors.

```sh
attacker@teamserver ~> ssh -N -R 8443:localhost:443 attacker@10.10.0.100
```

#### Test SSH tunnel

```sh
attacker@redictor curl -v https://localhost:8443/r1
```

Note: If we are receiving certificate errors from the above command, we'll need to add the .crt to our trusted certificates in `/usr/local/share/ca-certificates` and run **`update-ca-certificates`**`.`

```
scp localhost.crt attacker@10.10.0.100:/home/attacker/
```



## Enable Apache Redirection
