# SQL Injection&#x20;

The most common locations where SQL injections arise are:

* In `UPDATE` statements, within the updated values or the `WHERE` clause.
* In `INSERT` statements, within the inserted values.
* In `SELECT` statements, within the table or column name.
* In `SELECT` statements, within the `ORDER BY` clause.

_**SQL Injection Examples:**_

* [Retrieving hidden data](https://portswigger.net/web-security/sql-injection#retrieving-hidden-data), where you can modify a SQL query to return additional results.
* [Subverting application logic](https://portswigger.net/web-security/sql-injection#subverting-application-logic), where you can change a query to interfere with the application's logic.
* [UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks), where you can retrieve data from different database tables.
* [Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind), where the results of a query you control are not returned in the application's responses.

