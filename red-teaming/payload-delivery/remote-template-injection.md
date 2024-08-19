# Remote Template Injection



## Introduction

Microsoft Word has the option to create documents using a template. Whenever a Word documents with a template is being written / read, the template can either be wordloaded/loaded from the local, or a remote machine. Whenever the victim opens the Word Document, the Document will fetch the malicious template from the attacker's server, and execute it.

<figure><img src="../../.gitbook/assets/Screenshot 2024-08-19 at 2.28.48 PM.png" alt=""><figcaption><p><a href="https://blog.sunggwanchoi.com/remote-template-injection/">https://blog.sunggwanchoi.com/remote-template-injection/</a></p></figcaption></figure>





## Crating the Template

We can use the tool [remoteinjector](https://github.com/JohnWoodman/remoteinjector) to automate the process so we don't have to update any XML.

## OPSEC
