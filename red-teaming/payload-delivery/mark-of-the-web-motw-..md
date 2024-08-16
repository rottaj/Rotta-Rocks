# Mark of the Web (MOTW).



## Introduction

Any file that is downloaded using a browser outside of a trusted zone (the web) will be marked with the "Mark of the Web" (MOTW). This get's embedded into a file which says it was downloaded from an untrusted location and is possibly malicious. This datastream is known as a "Zone Identifier".

The possible zones are:

* 0 => Local computer
* 1 => Local intranet
* 2 => Trusted sites
* 3 => Internet
* 4 => Restricted sites

Files (and thus our payloads) with MOTW are handled with additional scrutiny and require click verification through warnings. Additionally, If MS Office "block macros downloaded from the Internet" is enabled, a user cannot run a macro-enabled document even if they wanted to.  This will [soon be](https://www.bleepingcomputer.com/news/microsoft/microsoft-plans-to-kill-malware-delivery-via-office-macros/) the default setting.

**A breath of fresh air**: Files emailed internally are <mark style="color:red;">**not**</mark> marked with with a zone identifier.

\
