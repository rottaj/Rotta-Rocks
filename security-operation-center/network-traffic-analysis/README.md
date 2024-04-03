# Network Traffic Analysis

## Introduction

Network Traffic Analysis (NTA) is the process of examining network traffic to characterize common ports and protocols utilized.

Doing so we establish a baseline for our environment and can respond to threats, and insure the greatest possible insight for our network.

* **Collecting** real-time traffic within the network to analyze upcoming threats.
* **Setting** a baseline for day-to-day network communications.
* **Identifying** and analyzing traffic from non-standard ports, suspicious hosts, and issues with network protocols. (HTTP, SMB, TCP, etc.)
* **Detecting** malware on the wire. (ransomware, exploits, non-standard interactions)

## BPF Syntax

Berkely Packet Filters is a technology that enables a raw interface to read and write from the Data-Link layer. More on this later.

## Networking Reference

### OSI / TCP-IP Models

Here is a side by side of the <mark style="color:yellow;">**Open Systems Interconnect (OSI)**</mark> model and the <mark style="color:yellow;">Transmission Control Protocol - Internet Protocol (TCP-IP)</mark> model side by side.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### PDU Example

Protocol Data Units (PDU) is a data packet made up of control information and data encapsulated from each layer of the OSI model.&#x20;

<figure><img src="../../.gitbook/assets/image (5) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Tools

**Common Traffic Analysis Tools**

| **Tool**                | **Description**                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tcpdump`               | [tcpdump](https://www.tcpdump.org/) is a command-line utility that, with the aid of LibPcap, captures and interprets network traffic from a network interface or capture file.                                                                                                                                                                                                                                  |
| `Tshark`                | [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) is a network packet analyzer much like TCPDump. It will capture packets from a live network or read and decode from a file. It is the command-line variant of Wireshark.                                                                                                                                                                         |
| `Wireshark`             | [Wireshark](https://www.wireshark.org/) is a graphical network traffic analyzer. It captures and decodes frames off the wire and allows for an in-depth look into the environment. It can run many different dissectors against the traffic to characterize the protocols and applications and provide insight into what is happening.                                                                          |
| `NGrep`                 | [NGrep](https://github.com/jpr5/ngrep) is a pattern-matching tool built to serve a similar function as grep for Linux distributions. The big difference is that it works with network traffic packets. NGrep understands how to read live traffic or traffic from a PCAP file and utilize regex expressions and BPF syntax. This tool shines best when used to debug traffic from protocols like HTTP and FTP.  |
| `tcpick`                | [tcpick](http://tcpick.sourceforge.net/index.php?p=home.inc) is a command-line packet sniffer that specializes in tracking and reassembling TCP streams. The functionality to read a stream and reassemble it back to a file with tcpick is excellent.                                                                                                                                                          |
| `Network Taps`          | Taps ([Gigamon](https://www.gigamon.com/), [Niagra-taps](https://www.niagaranetworks.com/products/network-tap)) are devices capable of taking copies of network traffic and sending them to another place for analysis. These can be in-line or out of band. They can actively capture and analyze the traffic directly or passively by putting the original packet back on the wire as if nothing had changed. |
| `Networking Span Ports` | [Span Ports](https://en.wikipedia.org/wiki/Port\_mirroring) are a way to copy frames from layer two or three networking devices during egress or ingress processing and send them to a collection point. Often a port is mirrored to send those copies to a log server.                                                                                                                                         |
| `Elastic Stack`         | The [Elastic Stack](https://www.elastic.co/elastic-stack) is a culmination of tools that can take data from many sources, ingest the data, and visualize it, to enable searching and analysis of it.                                                                                                                                                                                                            |
| `SIEMS`                 | `SIEMS` (such as [Splunk](https://www.splunk.com/en\_us)) are a central point in which data is analyzed and visualized. Alerting, forensic analysis, and day-to-day checks against the traffic are all use cases for a SIEM.                                                                                                                                                                                    |
