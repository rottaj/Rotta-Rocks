# Initial Enumeration of Network

Here are some main tasks we need to accomplish when initially enumerating a network:

* Enumerate the internal network, identifying hosts, critical services, and potential avenues for a foothold.
* This can include active and passive measures to identify users, hosts, and vulnerabilities we may be able to take advantage of to further our access.
* Document any findings we come across for later use. Extremely important!
*   **Key Data Points**

    | **Data Point**                  | **Description**                                                                                                                 |
    | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
    | `AD Users`                      | We are trying to enumerate valid user accounts we can target for password spraying.                                             |
    | `AD Joined Computers`           | Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc. |
    | `Key Services`                  | Kerberos, NetBIOS, LDAP, DNS                                                                                                    |
    | `Vulnerable Hosts and Services` | Anything that can be a quick win. ( a.k.a an easy host to exploit and gain a foothold)                                          |

### Tactics, Techniques, and Procedures (TTPs)

We will start with `passive` identification of any hosts in the network, followed by `active` validation of the results to find out more about each host (what services are running, names, potential vulnerabilities, etc.)

_<mark style="color:red;">**IMPORTANT:**</mark>_ After we have accomplished these enumerating a new host, we should stop and regroup and look at what info we have.

{% embed url="https://www.cisa.gov/sites/default/files/publications/Supply_Chain_Compromise_Detecting_APT_Activity_from_known_TTPs.pdf" %}

### Identifying Hosts

We can use `Wireshark` and `TCPDump` to "put our ear to the wire" and see what hosts and types of network traffic we can capture.&#x20;

**Wireshark Output**

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-15 125246.png" alt=""><figcaption></figcaption></figure>

ARP packets make us aware of the hosts: 172.16.5.5, 172.16.5.25 172.16.5.50, 172.16.5.100, and 172.16.5.125.

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-15 125358.png" alt=""><figcaption></figcaption></figure>

MDNS makes us aware of the ACADEMY-EA-WEB01 host.



If we are on a host without a GUI (which is typical), we can use [tcpdump](https://linux.die.net/man/8/tcpdump), [net-creds](https://github.com/DanMcInerney/net-creds), and [NetMiner](http://www.netminer.com/main/main-read.do), etc., to perform the same functions. We can also use tcpdump to save a capture to a .pcap file, transfer it to another host, and open it in Wireshark.

**Tcpdump Output**

```shell-session
attacker@kali$ sudo tcpdump -i ens224 
```

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-15 125526.png" alt=""><figcaption><p>Our first look at network traffic pointed us to a couple of hosts via <code>MDNS</code> and <code>ARP</code></p></figcaption></figure>

&#x20;Depending on the host you are on, you may already have a network monitoring tool built-in, such as `pktmon.exe,`which was added to all editions of Windows 10.

_<mark style="color:red;">**NOTE:**</mark>_ for testing, it's always a good idea to save the PCAP traffic you capture.

[Responder](https://github.com/lgandx/Responder-Windows) is a tool built to listen, analyze, and poison `LLMNR`, `NBT-NS`, and `MDNS` requests and responses.

**Starting Responder**

```bash
sudo responder -I ens224 -A
```

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-15 130734.png" alt=""><figcaption></figcaption></figure>

**FPing Active Checks**

We will perform a ping sweep of the subnet using Fping. FPing allows us to issue ICMP packets against multiple hosts at once. _<mark style="color:red;">**NOTE:**</mark>_ Windows Defender blocks ICMP by default so this may not work.

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ fping -asgq 172.16.5.0/23
</strong>
172.16.5.5
172.16.5.25
172.16.5.50
172.16.5.100
172.16.5.125
172.16.5.200
172.16.5.225
172.16.5.238
172.16.5.240

     510 targets
       9 alive
     501 unreachable
</code></pre>

**Nmap Scanning**

```bash
attacker@kali sudo nmap -v -A -iL hosts.txt -oN /home/attacker/Documents/host-enum
```

The [-A (Aggressive scan options)](https://nmap.org/book/man-misc-options.html) scan will perform several functions. One of the most important is a quick enumeration of well-known ports to include web services, domain services, etc.

### Identifying Hosts

From the nmap output we can Identify what operating systems these hosts are running as well as their versions. Strangely enough, it is still common to see legacy software or end-of-life operating systems being used in enterprise environments.

### Identifying Users

We need to find our way to a domain user account or `SYSTEM` level access on a domain-joined host so we can gain a foothold and start the real fun. The best way is by finding credentials, either plaintext or a NTLM password hash.

Obtaining a valid user with credentials is critical in the early stages of an internal penetration test.

### Kerbrute - Internal AD Username Enumeration

[Kerbrute](https://github.com/ropnop/kerbrute) can be a stealthier option for domain account enumeration. It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts.

&#x20;We will use Kerbrute in conjunction with the `jsmith.txt` or `jsmith2.txt` user lists from [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames).

\
**Cloning Kerbrute GitHub Repo**

```shell-session
attacker@kali $ sudo git clone https://github.com/ropnop/kerbrute.git
```

**Compiling for Multiple Platforms and Architectures**

```shell-session
attacker@kali$ sudo make all
```

**Testing the kerbrute\_linux\_amd64 Binary**

```shell-session
attacker@kali$ ./kerbrute_linux_amd64 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop
```

**Enumerating Users with Kerbrute**

```shell-session
attacker@kali$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users

2021/11/17 23:01:46 >  Using KDC(s):
2021/11/17 23:01:46 >   172.16.5.5:88
2021/11/17 23:01:46 >  [+] VALID USERNAME:       jjones@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       sbrown@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       tjohnson@INLANEFREIGHT.LOCAL
2021/11/17 23:01:50 >  [+] VALID USERNAME:       evalentin@INLANEFREIGHT.LOCAL
```



### Identifying Potential Vulnerabilities

\
The [local system](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account) account `NT AUTHORITY\SYSTEM` is a built-in account in Windows operating systems. It has the highest level of access in the OS and is used to run most Windows services.&#x20;

It is also very common for third-party services to run in the context of this account by default.\
\
Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account.

_**There are several ways to gain SYSTEM-level access on a host, including but not limited to:**_

* Remote Windows exploits such as MS08-067, EternalBlue, or BlueKeep.
* Abusing a service running in the context of the `SYSTEM account`, or abusing the service account `SeImpersonate` privileges using [Juicy Potato](https://github.com/ohpe/juicy-potato). This type of attack is possible on older Windows OS' but not always possible with Windows Server 2019.
* Local privilege escalation flaws in Windows operating systems such as the Windows 10 Task Scheduler 0-day.
* Gaining admin access on a domain-joined host with a local account and using Psexec to launch a SYSTEM cmd window

_**By gaining SYSTEM-level access on a domain-joined host, you will be able to perform actions such as, but not limited to:**_

* Enumerate the domain using built-in tools or offensive tools such as BloodHound and PowerView.
* Perform Kerberoasting / ASREPRoasting attacks within the same domain.
* Run tools such as Inveigh to gather Net-NTLMv2 hashes or perform SMB relay attacks.
* Perform token impersonation to hijack a privileged domain user account.
* Carry out ACL attacks.



_<mark style="color:red;">**BE QUITE IMPORTANT:**</mark>_\
`stealth` is of concern. Throwing Nmap at an entire network is not exactly quiet, and many of the tools we commonly use on a penetration test will trigger alarms for an educated and prepared SOC or Blue Teamer. Always be sure to clarify the goal of your assessment with the client in writing before it begins.

###
