# Tcpdump

## Introduction

[Tcpdump](https://www.tcpdump.org/) is a network traffic sniffer that directly capture and interpret data frames from a file or network interface. It's built for Unix-based operating systems and recommended to use in WSL if on Windows.

## Basic Commands

### Include ASCII & Hex Output

```shell-session
$ sudo tcpdump -i eth0 -X

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
11:10:34.972248 IP 172.16.146.2.57170 > ec2-99-80-22-207.eu-west-1.compute.amazonaws.com.https: Flags [P.], seq 2612172989:2612173026, ack 3165195759, win 501, options [nop,nop,TS val 1368561052 ecr 65712142], length 37
    0x0000:  4500 0059 4352 4000 4006 3f1b ac10 9202  E..YCR@.@.?.....
    0x0010:  6350 16cf df52 01bb 9bb2 98bd bca9 0def  cP...R..........
    0x0020:  8018 01f5 b87d 0000 0101 080a 5192 959c  .....}......Q...
    0x0030:  03ea b00e 1703 0300 2000 0000 0000 0000  ................
    0x0040:  0adb 84ac 34b4 910a 0fb4 2f49 9865 eb45  ....4...../I.e.E
    0x0050:  883c eafd 8266 3e23 88                   .<...f>#.
```

### Save PCAP Output to file

```shell-session
$ sudo tcpdump -i eth0 -w ~/output.pcap

tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
10 packets captured
131 packets received by filter
0 packets dropped by kernel
```

### Reading Output From a file

```shell-session
$ sudo tcpdump -r ~/output.pcap

reading from file /home/trey/output.pcap, link-type EN10MB (Ethernet), snapshot length 262144
11:15:40.321509 IP 172.16.146.2.57236 > ec2-99-80-22-207.eu-west-1.compute.amazonaws.com.https: Flags [P.], seq 2751910362:2751910399, ack 946558143, win 501, options [nop,nop,TS val 1368866401 ecr 65790024], length 37
11:15:40.337302 IP 172.16.146.2.55416 > 172.67.1.1.https: Flags [P.], seq 3766493458:3766493533, ack 4098207917, win 501, length 75
11:15:40.398103 IP 172.67.1.1.https > 172.16.146.2.55416: Flags [.], ack 75, win 73, length 0
```

### Common Switches

<table data-header-hidden><thead><tr><th width="133" align="center"></th><th></th></tr></thead><tbody><tr><td align="center"><strong>Switch Command</strong></td><td><strong>Result</strong></td></tr><tr><td align="center">D</td><td>Will display any interfaces available to capture from.</td></tr><tr><td align="center">i</td><td>Selects an interface to capture from. ex. -i eth0</td></tr><tr><td align="center">n</td><td>Do not resolve hostnames.</td></tr><tr><td align="center">nn</td><td>Do not resolve hostnames or well-known ports.</td></tr><tr><td align="center">e</td><td>Will grab the ethernet header along with upper-layer data.</td></tr><tr><td align="center">X</td><td>Show Contents of packets in hex and ASCII.</td></tr><tr><td align="center">XX</td><td>Same as X, but will also specify ethernet headers. (like using Xe)</td></tr><tr><td align="center">v, vv, vvv</td><td>Increase the verbosity of output shown and saved.</td></tr><tr><td align="center">c</td><td>Grab a specific number of packets, then quit the program.</td></tr><tr><td align="center">s</td><td>Defines how much of a packet to grab.</td></tr><tr><td align="center">S</td><td>change relative sequence numbers in the capture display to absolute sequence numbers. (13248765839 instead of 101)</td></tr><tr><td align="center">q</td><td>Print less protocol information.</td></tr><tr><td align="center">r file.pcap</td><td>Read from a file.</td></tr><tr><td align="center">w file.pcap</td><td>Write into a file</td></tr></tbody></table>



## Packet Filtering



### Host Filter

This filter is often used when we want to examine only a specific host or server.

```shell-session
$ sudo tcpdump -i eth0 host 172.16.146.2

14:50:53.072536 IP 172.16.146.2.48738 > ec2-52-31-199-148.eu-west-1.compute.amazonaws.com.https: Flags [P.], seq 3400465007:3400465044, ack 254421756, win 501, options [nop,nop,TS val 220968655 ecr 80852594], length 37
14:50:53.108740 IP 172.16.146.2.55606 > 172.67.1.1.https: Flags [P.], seq 4227143181:4227143273, ack 1980233980, win 21975, length 92
14:50:53.173084 IP 172.67.1.1.https > 172.16.146.2.55606: Flags [.], ack 92, win 69, length 0
```

### Protocol Filter

```shell-session
$ sudo tcpdump -i eth0 udp

06:17:09.864896 IP dialin-145-254-160-237.pools.arcor-ip.net.3009 > 145.253.2.203.domain: 35+ A? pagead2.googlesyndication.com. (47)
06:17:10.225414 IP 145.253.2.203.domain > dialin-145-254-160-237.pools.arcor-ip.net.3009: 35 4/0/0 CNAME pagead2.google.com., CNAME pagead.google.akadns.net.
```

### Port Filter

```shell-session
$ sudo tcpdump -i eth0 tcp port 443

06:17:07.311224 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [S], seq 951057939, win 8760, options [mss 1460,nop,nop,sackOK], length 0
06:17:08.222534 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [S.], seq 290218379, ack 951057940, win 5840, options [mss 1380,nop,nop,sackOK], length 0
```

### Source / Destination Filter

Source and destination allow us to work with the directions of communication

```shell-session
$ sudo tcpdump -i eth0 src host 172.16.146.2

14:53:36.267059 IP 172.16.146.2.36424 > 172.16.146.1.domain: 40873+ PTR? 148.199.31.52.in-addr.arpa. (44)
14:53:36.267880 IP 172.16.146.2.51151 > 172.16.146.1.domain: 10032+ PTR? 2.146.16.172.in-addr.arpa. (43)
```

### Port Range Filter

```shell-session
$ sudo tcpdump -i eth0 portrange 0-1024

13:10:35.093217 IP 172.16.146.2.48078 > 172.16.146.1.domain: 30234+ A? ocsp.pki.goog. (31)
13:10:35.093334 IP 172.16.146.2.48078 > 172.16.146.1.domain: 32024+ AAAA? ocsp.pki.goog. (31)
```

### Less / Greater Filter

We can look for any packets less than or greater to a specified byte.

```shell-session
$ sudo tcpdump -i eth0 less 64

06:17:07.311224 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [S], seq 951057939, win 8760, options [mss 1460,nop,nop,sackOK], length 0
06:17:08.222534 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [S.], seq 290218379, ack 951057940, win 5840, options [mss 1380,nop,nop,sackOK], length 0
```

### AND Filter

This is a great modifier than allows us to chain multiple filters.

```shell-session
$ sudo tcpdump -i eth0 host 192.168.0.1 and port 23

21:12:38.387203 IP 192.168.0.2.1550 > 192.168.0.1.telnet: Flags [S], seq 2579865836, win 32120, options [mss 1460,sackOK,TS val 10233636 ecr 0,nop,wscale 0], length 0
21:12:38.389728 IP 192.168.0.1.telnet > 192.168.0.2.1550: Flags [S.], seq 401695549, ack 2579865837, win 17376, options [mss 1448,nop,wscale 0,nop,nop,TS val 2467372 ecr 10233636], length 0
```

### OR Filter

Like AND this is another modifier that allows us to chain conditions.

```shell-session
$ sudo tcpdump -r sus.pcap icmp or host 172.16.146.1

reading from file sus.pcap, link-type EN10MB (Ethernet), snapshot length 262144
14:54:03.659163 IP 172.16.146.2 > dns.google: ICMP echo request, id 51661, seq 21, length 64
```

### NOT Filter

We can chain and excluse data with NOT.

```shell-session
$ sudo tcpdump -r sus.pcap not icmp

14:54:03.879882 ARP, Request who-has 172.16.146.1 tell 172.16.146.2, length 28
14:54:03.880266 ARP, Reply 172.16.146.1 is-at 8a:66:5a:11:8d:64 (oui Unknown), length 46
14:54:16.541657 IP 172.16.146.2.55592 > ec2-52-211-164-46.eu-west-1.compute.amazonaws.com.https: Flags [P.], seq 3569937476:3569937513, ack 2948818703, win 501, options [nop,nop,TS val 713252991 ecr 12282469], length 37
```

### Utilizing Source with Port as a Filter

This is a good command for viewing all outbound traffic over a specific port.

```shell-session
$ sudo tcpdump -i eth0 tcp src port 80

06:17:08.222534 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [S.], seq 290218379, ack 951057940, win 5840, options [mss 1380,nop,nop,sackOK], length 0
06:17:08.783340 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], ack 480, win 6432, length 0
```

### Using Destination in combination with the Net Filter

This filter can utilize the common protocol name or protocol number for any IP, IPv6.

```shell-session
$ sudo tcpdump -i eth0 dest net 172.16.146.0/24

16:33:14.376003 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [.], ack 1486880537, win 316, options [nop,nop,TS val 2311579424 ecr 263866084], length 0
16:33:14.442123 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [P.], seq 0:385, ack 1, win 316, options [nop,nop,TS val 2311579493 ecr 263866084], length 385
```

###

## Tips & Tricks

### Piping a Capture to Grep

```shell-session
$ sudo tcpdump -Ar http.cap -l | grep 'mailto:*'

reading from file http.cap, link-type EN10MB (Ethernet), snapshot length 65535
  <a href="mailto:ethereal-web[AT]ethereal.com">ethereal-web[AT]ethereal.com</a>
  <a href="mailto:free-support[AT]thewrittenword.com">free-support[AT]thewrittenword.com</a>
  <a href="mailto:ethereal-users[AT]ethereal.com">ethereal-users[AT]ethereal.com</a>
  <a href="mailto:ethereal-web[AT]ethereal.com">ethereal-web[AT]ethereal.com</a>
```

### Looking for TCP Protocol Flags

```shell-session
$ tcpdump -i eth0 'tcp[13] &2 != 0'
```

### Hunting for SYN Flags

```shell-session
$ sudo tcpdump -i eth0 'tcp[13] &2 != 0'

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
15:18:14.630993 IP 172.16.146.2.56244 > 172.67.1.1.https: Flags [S], seq 122498858, win 64240, options [mss 1460,sackOK,TS val 534699017 ecr 0,nop,wscale 7], length 0
15:18:14.654698 IP 172.67.1.1.https > 172.16.146.2.56244: Flags [S.], seq 3728841459, ack 122498859, win 65535, options [mss 1400,nop,nop,sackOK,nop,wscale 10], length 0
```





## Extra / Reference

### Protocol Request For Comments (RFC)

<table data-header-hidden><thead><tr><th width="238"></th><th></th></tr></thead><tbody><tr><td><strong>Link</strong></td><td><strong>Description</strong></td></tr><tr><td><a href="https://tools.ietf.org/html/rfc791">IP Protocol</a></td><td><code>RFC 791</code> describes IP and its functionality.</td></tr><tr><td><a href="https://tools.ietf.org/html/rfc792">ICMP Protocol</a></td><td><code>RFC 792</code> describes ICMP and its functionality.</td></tr><tr><td><a href="https://tools.ietf.org/html/rfc793">TCP Protocol</a></td><td><code>RFC 793</code> describes the TCP protocol and how it functions.</td></tr><tr><td><a href="https://tools.ietf.org/html/rfc768">UDP Protocol</a></td><td><code>RFC 768</code> describes UDP and how it operates.</td></tr><tr><td><a href="https://en.wikipedia.org/wiki/List_of_RFCs#Topical_list">RFC Quick Links</a></td><td>This Wikipedia article contains a large list of protocols tied to the RFC that explains their implementation.</td></tr></tbody></table>
