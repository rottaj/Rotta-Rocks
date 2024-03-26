# Incident Response Process

## Introduction

When identifying incidents the following is important:

* Proper preparation is a key ingredient in this process.
* Having a firm handle on attack vectors is required.
* Everything that exists in the cyber world should be considered an attack vector.&#x20;



## Incident Response Life-cycle

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>





## Incident Response Process



### First Steps - Identifying the Incident

* Start a log book
  * Use this to identify all steps taken. Keep current throughout course of incident.
* Assign an Incident Handler.
* Coordinate with Incident Response Team.
* Determine next steps:
  * Is attack on-going? Is it active at this time, or is it a past incident?&#x20;
  * What's the current impact? HIPAA, PII, etc.
* Isolate any affected systems/networks.
* Notify appropriate entities. Internal or external.



### Second Steps - Managing the Incident

* **Containment**
  * An essential element in containment is decision making.
  *   Many companies fail to provide authority for:

      * Shutting systems down.
      * Disconnecting a system from network.
      * Disabling functionality.


* All steps of managing the incident must be documented in order to provide proper recovery from an incident.
* **Eradication**
  * Removing the attacker and all components of the attack.
    * This can be as simple as deleting malware and disabling breached user accounts.
    * Reset all affected systems, user passwords, and service passwords.
    * Update all anti-malware/virus and search for new IOC's.
    * Correct all vulnerabilties discovered.
    * Clean registires and scan for memory resident malware.



## Chain of Custody

The Chain of Custody is the trail of your evidence covering every person who touches it or possesses the item. For example:&#x20;

An Security Analyst I notices a anomaly in the network logs and passes it to Security Analyst II who then passes it to their Incident Response Team. The chain of custody is:

* Security Analyst I -> Security Analyst II -> IR Team.&#x20;

**NOTE:** Many industry regulations require this!! (HIPAA).



## Tools

* SIEM (Security Information & Event Management).
* EDR (Endpoint Detection and Response).
* MDR (Managed Detection and Response) also known as SOC-as-service.
* IDS/IPS (Intrusion Detection/Intrusion Prevention System).
* AV (Anti-virus. Can also include malware protection).

