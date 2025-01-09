# C2 Infrastructure Design



## Design

Adversary simulation should be located on-premise, or in an environment tightly controlled by the red teaming company.&#x20;



## OPSEC safe method of connect to infrastructure and redirectors

<mark style="color:red;">**IMPORTANT**</mark>: We want to ensure any resources / servers we do not entirely own and control does not contain any sensitive credentials or data.

### SSH Tunnels

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

## Redirectors

It's important to never store any data on a redirector, traffic should only transmit through it.&#x20;

* We can setup an SSH or VPN tunnel from the C2 server to the HTTP redirector. We want it done this way so no sensitive private keys or credentials for the C2 server on our redirector.

### Serverless Redirectors

CDN's, AWS Lambda, Azure Functions, CloudFlare Workers can be used as "Serverless" redirectors.

## SSL Certificates

It's important to generate a SSL certificate when registering a new domain, we then create a Certificate Signing Request (CSR), which is a message sent to a Certiciate Authority (CA) to apply for a digital certificate. Essentially, it verifies that we are the domain owner.

### Generate SSL Certificate (Openssl) & CSR

#### Create Certificate

```sh
$ openssl req -new -key attacker-domain.key -out attacker-domain.csr
```

#### Submit to Certificate Authority (CA)

Next is to submit our certificate to a Certificate Authority (CA) such as Let's Encrypt, VeriSign, GlobalSign, or DigiCert, etc.

### Upload SSL Certificate to Apache

We can now upload our SSL certificate to`/etc/apache2/sites-enabled/default-ssl.conf`:

Replace snakeoil on lines 32-33 with the path to our certificate.

```
SSLCertificateFile     /etc/ssl/certs/ssl-cert-snakeoil.pem
SSLCertificateKeyFile  /etc/ssl/private/ssl-cert-snakeoil.key
```

**Restart Apache**

```
$ sudo systemctl restart apache2
```

## Beacon Certificates

HTTPS listeners in CobaltStrike use their own self-signed certificates by default. We should include our own keypairs.
