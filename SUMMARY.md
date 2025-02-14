# Table of contents

## ☕ General

* [About Me](README.md)
* [Recently Added](general/recently-added.md)

## ☣️ Offensive Tool Development

* [Windows Internals](offensive-tool-development/windows-internals/README.md)
  * [Registers](offensive-tool-development/windows-internals/registers.md)
  * [x64 Calling Convention](offensive-tool-development/windows-internals/x64-calling-convention.md)
  * [PE File Format](offensive-tool-development/windows-internals/pe-file-format/README.md)
    * [PE File Structure](offensive-tool-development/windows-internals/pe-file-format/pe-file-structure.md)
    * [DOS Header, DOS Stub, & Rich Header](offensive-tool-development/windows-internals/pe-file-format/dos-header-dos-stub-and-rich-header.md)
    * [NT Headers](offensive-tool-development/windows-internals/pe-file-format/nt-headers.md)
    * [Data Directories & Section Headers](offensive-tool-development/windows-internals/pe-file-format/data-directories-and-section-headers.md)
    * [Import Directory Table, ILT & IAT](offensive-tool-development/windows-internals/pe-file-format/import-directory-table-ilt-and-iat.md)
    * [Image Export Table](offensive-tool-development/windows-internals/pe-file-format/image-export-table.md)
    * [PE Base Relocations](offensive-tool-development/windows-internals/pe-file-format/pe-base-relocations.md)
  * [Processes & PEB Structure](offensive-tool-development/windows-internals/processes-and-peb-structure.md)
  * [Threads & TEB Structure](offensive-tool-development/windows-internals/threads-and-teb-structure.md)
  * [Event Tracing for Windows (ETW)](offensive-tool-development/windows-internals/event-tracing-for-windows-etw/README.md)
    * [Interacting with ETW](offensive-tool-development/windows-internals/event-tracing-for-windows-etw/interacting-with-etw.md)
    * [ETW Tools](offensive-tool-development/windows-internals/event-tracing-for-windows-etw/etw-tools.md)
* [Enumeration](offensive-tool-development/enumeration/README.md)
  * [Process Enumeration](offensive-tool-development/enumeration/process-enumeration/README.md)
    * [CreateToolhelp32Snapshot](offensive-tool-development/enumeration/process-enumeration/createtoolhelp32snapshot.md)
    * [EnumProcesses (psapi.h)](offensive-tool-development/enumeration/process-enumeration/enumprocesses-psapi.h.md)
    * [NtQuerySystemInformation](offensive-tool-development/enumeration/process-enumeration/ntquerysysteminformation.md)
    * [NtQueryInformationProcess](offensive-tool-development/enumeration/process-enumeration/ntqueryinformationprocess.md)
  * [Thread Enumeration](offensive-tool-development/enumeration/thread-enumeration/README.md)
    * [CreateToolhelp32Snapshot](offensive-tool-development/enumeration/thread-enumeration/createtoolhelp32snapshot.md)
    * [NtQuerySystemInformation](offensive-tool-development/enumeration/thread-enumeration/ntquerysysteminformation.md)
  * [DLL Enumeration](offensive-tool-development/enumeration/dll-enumeration.md)
* [Memory Allocation](offensive-tool-development/memory-allocation/README.md)
  * [Private Memory Allocation](offensive-tool-development/memory-allocation/private-memory-allocation.md)
  * [Memory Mapping](offensive-tool-development/memory-allocation/memory-mapping.md)
* [Access Tokens](offensive-tool-development/access-tokens/README.md)
  * [Page 1](offensive-tool-development/access-tokens/page-1.md)
* [Techniques and Exploitation Methods](offensive-tool-development/techniques-and-exploitation-methods/README.md)
  * [Thread Hijacking](offensive-tool-development/techniques-and-exploitation-methods/thread-hijacking.md)
  * [APC Injection](offensive-tool-development/techniques-and-exploitation-methods/apc-injection.md)
  * [Function Stomping](offensive-tool-development/techniques-and-exploitation-methods/function-stomping.md)
  * [DLL Sideloading](offensive-tool-development/techniques-and-exploitation-methods/dll-sideloading.md)
  * [Process Hollowing](offensive-tool-development/techniques-and-exploitation-methods/process-hollowing.md)
  * [Injection Techniques](offensive-tool-development/techniques-and-exploitation-methods/injection-techniques/README.md)
    * [Reflective DLL Injection](offensive-tool-development/techniques-and-exploitation-methods/injection-techniques/reflective-dll-injection.md)
    * [Local PE Injection](offensive-tool-development/techniques-and-exploitation-methods/injection-techniques/local-pe-injection.md)
    * [Callback Process Injection](offensive-tool-development/techniques-and-exploitation-methods/injection-techniques/callback-process-injection.md)
    * [Shellcode Reflective DLL Injection](offensive-tool-development/techniques-and-exploitation-methods/injection-techniques/shellcode-reflective-dll-injection.md)
    * [DLL Injection](offensive-tool-development/techniques-and-exploitation-methods/injection-techniques/dll-injection.md)
  * [ProxyAlloc](offensive-tool-development/techniques-and-exploitation-methods/proxyalloc.md)
* [PE Tips & Tricks](offensive-tool-development/pe-tips-and-tricks/README.md)
  * [Parsing PE Headers](offensive-tool-development/pe-tips-and-tricks/parsing-pe-headers.md)
  * [Patching IAT](offensive-tool-development/pe-tips-and-tricks/patching-iat.md)
  * [Patching Base Relocations](offensive-tool-development/pe-tips-and-tricks/patching-base-relocations.md)
  * [Fixing Memory Permissions](offensive-tool-development/pe-tips-and-tricks/fixing-memory-permissions.md)
  * [Embed an EXE inside a LNK](offensive-tool-development/pe-tips-and-tricks/embed-an-exe-inside-a-lnk.md)
  * [PE Infection](offensive-tool-development/pe-tips-and-tricks/pe-infection.md)
* [Staging](offensive-tool-development/staging/README.md)
  * [Fetch Payload from Web Server](offensive-tool-development/staging/fetch-payload-from-web-server.md)
  * [Fetch DLL from Web Server](offensive-tool-development/staging/fetch-dll-from-web-server.md)
* [Bypassing AV](offensive-tool-development/bypassing-av/README.md)
  * [String Hashing](offensive-tool-development/bypassing-av/string-hashing.md)
  * [Hiding & Obfuscating IAT](offensive-tool-development/bypassing-av/hiding-and-obfuscating-iat.md)
  * [Custom WINAPI Functions](offensive-tool-development/bypassing-av/custom-winapi-functions/README.md)
    * [GetProcAddressHash](offensive-tool-development/bypassing-av/custom-winapi-functions/getprocaddresshash.md)
  * [File Bloating](offensive-tool-development/bypassing-av/file-bloating.md)
* [Evading EDR](offensive-tool-development/evading-edr/README.md)
  * [Payload Execution Control](offensive-tool-development/evading-edr/payload-execution-control.md)
  * [Wrapping NTAPI Functions](offensive-tool-development/evading-edr/wrapping-ntapi-functions/README.md)
    * [NtCreateUserProcess](offensive-tool-development/evading-edr/wrapping-ntapi-functions/ntcreateuserprocess.md)
    * [NtQuerySystemInformation](offensive-tool-development/evading-edr/wrapping-ntapi-functions/ntquerysysteminformation.md)
  * [NTDLL Unhooking](offensive-tool-development/evading-edr/ntdll-unhooking/README.md)
    * [NTDLL Unhooking - From Disk](offensive-tool-development/evading-edr/ntdll-unhooking/ntdll-unhooking-from-disk.md)
    * [NTDLL Unhooking - From KnownDlls](offensive-tool-development/evading-edr/ntdll-unhooking/ntdll-unhooking-from-knowndlls.md)
    * [NTDLL Unhooking - From Suspended Process](offensive-tool-development/evading-edr/ntdll-unhooking/ntdll-unhooking-from-suspended-process.md)
    * [NTDLL Unhooking - From Web Server](offensive-tool-development/evading-edr/ntdll-unhooking/ntdll-unhooking-from-web-server.md)
  * [PPID Spoofing](offensive-tool-development/evading-edr/ppid-spoofing.md)
  * [Call Stack Spoofing](offensive-tool-development/evading-edr/call-stack-spoofing.md)
  * [Call Stack Spoofing (Via Vector Exception Handling)](offensive-tool-development/evading-edr/call-stack-spoofing-via-vector-exception-handling.md)
  * [Proxying WinAPI's](offensive-tool-development/evading-edr/proxying-winapis.md)
  * [Module Stomping (& Process Hollowing)](offensive-tool-development/evading-edr/module-stomping-and-process-hollowing.md)
* [Anti-Analysis Techniques](offensive-tool-development/anti-analysis-techniques/README.md)
  * [Anti-Debugging Techniques](offensive-tool-development/anti-analysis-techniques/anti-debugging-techniques/README.md)
    * [Check If Running In a Debugger](offensive-tool-development/anti-analysis-techniques/anti-debugging-techniques/check-if-running-in-a-debugger.md)
    * [Self Deleting Malware](offensive-tool-development/anti-analysis-techniques/anti-debugging-techniques/self-deleting-malware.md)
  * [Anti-Virtual Environments (AVE) Techniques](offensive-tool-development/anti-analysis-techniques/anti-virtual-environments-ave-techniques/README.md)
    * [Detecting Hardware Specs](offensive-tool-development/anti-analysis-techniques/anti-virtual-environments-ave-techniques/detecting-hardware-specs.md)
    * [Delaying Execution](offensive-tool-development/anti-analysis-techniques/anti-virtual-environments-ave-techniques/delaying-execution.md)
    * [API Hammering](offensive-tool-development/anti-analysis-techniques/anti-virtual-environments-ave-techniques/api-hammering.md)
  * [Reducing Binary Entropy](offensive-tool-development/anti-analysis-techniques/reducing-binary-entropy.md)
  * [Brute Forcing Decryption Key](offensive-tool-development/anti-analysis-techniques/brute-forcing-decryption-key.md)
  * [Removing MSCRT](offensive-tool-development/anti-analysis-techniques/removing-mscrt.md)
  * [Hiding / Camouflaging IAT](offensive-tool-development/anti-analysis-techniques/hiding-camouflaging-iat.md)
* [API Hooking](offensive-tool-development/api-hooking/README.md)
  * [Userland Hooking](offensive-tool-development/api-hooking/userland-hooking.md)
  * [Custom Hooking Function](offensive-tool-development/api-hooking/custom-hooking-function.md)
  * [Open-Source Hooking Libraries](offensive-tool-development/api-hooking/open-source-hooking-libraries/README.md)
    * [Microsoft's Detours Library](offensive-tool-development/api-hooking/open-source-hooking-libraries/microsofts-detours-library.md)
    * [MinHook Library](offensive-tool-development/api-hooking/open-source-hooking-libraries/minhook-library.md)
* [Syscalls](offensive-tool-development/syscalls/README.md)
  * [NTAPI Syscall Process Injection](offensive-tool-development/syscalls/ntapi-syscall-process-injection.md)
  * [Direct Syscalls](offensive-tool-development/syscalls/direct-syscalls/README.md)
    * [SysWhispers](offensive-tool-development/syscalls/direct-syscalls/syswhispers.md)
  * [Indirect Syscalls](offensive-tool-development/syscalls/indirect-syscalls.md)
  * [Resolving Syscalls (Functions)](offensive-tool-development/syscalls/resolving-syscalls-functions.md)
* [C2 Development](offensive-tool-development/c2-development/README.md)
  * [Consensus & Design Patterns](offensive-tool-development/c2-development/consensus-and-design-patterns.md)
  * [Infrastructure](offensive-tool-development/c2-development/infrastructure.md)
  * [Teamserver](offensive-tool-development/c2-development/teamserver.md)
  * [Listeners](offensive-tool-development/c2-development/listeners.md)
  * [Agent Stubs](offensive-tool-development/c2-development/agent-stubs.md)
  * [Encrypting Communication](offensive-tool-development/c2-development/encrypting-communication.md)
* [User Defined Reflective Loader (UDRL)](offensive-tool-development/user-defined-reflective-loader-udrl.md)
* [MalDev Environment Setup](offensive-tool-development/maldev-environment-setup/README.md)
  * [Setting up Dev Box](offensive-tool-development/maldev-environment-setup/setting-up-dev-box.md)
  * [Setting up Pwn Box](offensive-tool-development/maldev-environment-setup/setting-up-pwn-box.md)
  * [Setting up Dev Server](offensive-tool-development/maldev-environment-setup/setting-up-dev-server.md)
  * [Commando VM](offensive-tool-development/maldev-environment-setup/commando-vm.md)
* [Maldev Checklist](offensive-tool-development/maldev-checklist.md)

## 👺 Red Teaming

* [Setting up Infrastructure](red-teaming/setting-up-infrastructure/README.md)
  * [C2 Infrastructure Design](red-teaming/setting-up-infrastructure/c2-infrastructure-design.md)
  * [Redirectors & Enabling Apache Redirection](red-teaming/setting-up-infrastructure/redirectors-and-enabling-apache-redirection.md)
  * [Beacon Staging](red-teaming/setting-up-infrastructure/beacon-staging.md)
* [External Recon](red-teaming/external-recon.md)
* [Initial Compromise](red-teaming/initial-compromise/README.md)
  * [Setting up Infrastructure](red-teaming/initial-compromise/setting-up-infrastructure.md)
  * [Password Spraying OWA](red-teaming/initial-compromise/password-spraying-owa.md)
  * [MS Office Phishing](red-teaming/initial-compromise/ms-office-phishing/README.md)
    * [VBA Macro Beacon](red-teaming/initial-compromise/ms-office-phishing/vba-macro-beacon.md)
    * [Remote Template Injection](red-teaming/initial-compromise/ms-office-phishing/remote-template-injection.md)
    * [HTML Smuggling](red-teaming/initial-compromise/ms-office-phishing/html-smuggling.md)
  * [Payload Delivery](red-teaming/initial-compromise/payload-delivery/README.md)
    * [MS Office Payloads](red-teaming/initial-compromise/payload-delivery/ms-office-payloads/README.md)
      * [Mark of the Web (MOTW).](red-teaming/initial-compromise/payload-delivery/ms-office-payloads/mark-of-the-web-motw-..md)
      * [Visual Basic Macro (VBA)](red-teaming/initial-compromise/payload-delivery/ms-office-payloads/visual-basic-macro-vba.md)
      * [Remote Template Injection](red-teaming/initial-compromise/payload-delivery/ms-office-payloads/remote-template-injection.md)
    * [SCR File Attack](red-teaming/initial-compromise/payload-delivery/scr-file-attack.md)
  * [Crafting the Email](red-teaming/initial-compromise/crafting-the-email.md)
  * [Browser In Browser Attack](red-teaming/initial-compromise/browser-in-browser-attack.md)
  * [EvilGinx](red-teaming/initial-compromise/evilginx.md)
* [Internal Recon & Enumeration](red-teaming/internal-recon-and-enumeration/README.md)
  * [Host Enumeration](red-teaming/internal-recon-and-enumeration/host-enumeration.md)
  * [Domain Enumeration](red-teaming/internal-recon-and-enumeration/domain-enumeration.md)
  * [PowerView & SharpView](red-teaming/internal-recon-and-enumeration/powerview-and-sharpview.md)
  * [ADSearch](red-teaming/internal-recon-and-enumeration/adsearch.md)
* [Privilege Escalation](red-teaming/privilege-escalation/README.md)
  * [Windows Services](red-teaming/privilege-escalation/windows-services.md)
  * [UAC Bypass](red-teaming/privilege-escalation/uac-bypass.md)
  * [Elevated SYSTEM Persistence](red-teaming/privilege-escalation/elevated-system-persistence.md)
* [Persistence](red-teaming/persistence/README.md)
  * [Scheduled Tasks](red-teaming/persistence/scheduled-tasks.md)
  * [Registry AutoRun](red-teaming/persistence/registry-autorun.md)
  * [Startup Folder](red-teaming/persistence/startup-folder.md)
  * [COM Hijacking](red-teaming/persistence/com-hijacking.md)
  * [Elevated SYSTEM Persistence](red-teaming/persistence/elevated-system-persistence.md)
* [Proxies, Pivoting, and Port Forwarding](red-teaming/proxies-pivoting-and-port-forwarding/README.md)
  * [SOCKS](red-teaming/proxies-pivoting-and-port-forwarding/socks.md)
  * [Proxychains (Linux)](red-teaming/proxies-pivoting-and-port-forwarding/proxychains-linux.md)
  * [Proxifier (Windows)](red-teaming/proxies-pivoting-and-port-forwarding/proxifier-windows.md)
  * [FoxyProxy & Browsers](red-teaming/proxies-pivoting-and-port-forwarding/foxyproxy-and-browsers.md)
  * [Reverse Port Forwarding](red-teaming/proxies-pivoting-and-port-forwarding/reverse-port-forwarding.md)
* [Credentials, Authentication, & Coercion](red-teaming/credentials-authentication-and-coercion/README.md)
  * [Kerberos & Active Directory Attacks](red-teaming/credentials-authentication-and-coercion/kerberos-and-active-directory-attacks.md)
  * [MimiKatz](red-teaming/credentials-authentication-and-coercion/mimikatz.md)
  * [Rubeus](red-teaming/credentials-authentication-and-coercion/rubeus.md)
  * [Kerberoasting](red-teaming/credentials-authentication-and-coercion/kerberoasting.md)
  * [ASREP Roasting](red-teaming/credentials-authentication-and-coercion/asrep-roasting.md)
  * [Kerberos Relay Attacks](red-teaming/credentials-authentication-and-coercion/kerberos-relay-attacks.md)
  * [NTLM Relay Attacks](red-teaming/credentials-authentication-and-coercion/ntlm-relay-attacks.md)
  * [WebDAV Relay Attacks](red-teaming/credentials-authentication-and-coercion/webdav-relay-attacks.md)
  * [Shadow Credentials](red-teaming/credentials-authentication-and-coercion/shadow-credentials.md)
  * [Resource-Based Constrained Delegation](red-teaming/credentials-authentication-and-coercion/resource-based-constrained-delegation.md)
  * [Unconstrained Delegation](red-teaming/credentials-authentication-and-coercion/unconstrained-delegation.md)
  * [Constrained Delegation](red-teaming/credentials-authentication-and-coercion/constrained-delegation.md)
* [Lateral Movement](red-teaming/lateral-movement/README.md)
  * [User Impersonation](red-teaming/lateral-movement/user-impersonation/README.md)
    * [Pass The Hash (PTH)](red-teaming/lateral-movement/user-impersonation/pass-the-hash-pth.md)
    * [Pass The Ticket (PTT)](red-teaming/lateral-movement/user-impersonation/pass-the-ticket-ptt.md)
    * [Overpass The Hash](red-teaming/lateral-movement/user-impersonation/overpass-the-hash.md)
    * [Token Impersonation ](red-teaming/lateral-movement/user-impersonation/token-impersonation.md)
    * [Token Store](red-teaming/lateral-movement/user-impersonation/token-store.md)
  * [Hunting for Lateral Movement](red-teaming/lateral-movement/hunting-for-lateral-movement.md)
  * [Techniques - Moving Laterally](red-teaming/lateral-movement/jumping-hosts.md)
* [Cobalt Strike](red-teaming/cobalt-strike/README.md)
  * [Start Team Server](red-teaming/cobalt-strike/start-team-server.md)
  * [Configure Listeners](red-teaming/cobalt-strike/configure-listeners.md)
  * [Beacons](red-teaming/cobalt-strike/beacons/README.md)
    * [UDRLess Beacon](red-teaming/cobalt-strike/beacons/udrless-beacon.md)
* [Cracking Passwords](red-teaming/cracking-passwords.md)
* [Tools & Checklists](red-teaming/tools-and-checklists/README.md)
  * [CRTO Cheat Sheet](red-teaming/tools-and-checklists/crto-cheat-sheet.md)
  * [Tools](red-teaming/tools-and-checklists/tools.md)
  * [Red Team Checklist](red-teaming/tools-and-checklists/red-team-checklist.md)

## 🪟 Active Directory

* [Active Directory Toolkit](active-directory/active-directory-toolkit/README.md)
  * [Windows Tools](active-directory/active-directory-toolkit/windows-tools/README.md)
    * [ActiveDirectory PowerShell Module](active-directory/active-directory-toolkit/windows-tools/activedirectory-powershell-module.md)
    * [PowerView](active-directory/active-directory-toolkit/windows-tools/powerview.md)
    * [SharpHound/BloodHound](active-directory/active-directory-toolkit/windows-tools/sharphound-bloodhound.md)
    * [Snaffler](active-directory/active-directory-toolkit/windows-tools/snaffler.md)
  * [Kali Linux Tools](active-directory/active-directory-toolkit/kali-linux-tools/README.md)
    * [Windapsearch & Ldapsearch](active-directory/active-directory-toolkit/kali-linux-tools/windapsearch-and-ldapsearch.md)
    * [CrackMapExec](active-directory/active-directory-toolkit/kali-linux-tools/crackmapexec.md)
    * [SMBMap](active-directory/active-directory-toolkit/kali-linux-tools/smbmap.md)
    * [rpcclient](active-directory/active-directory-toolkit/kali-linux-tools/rpcclient.md)
    * [Impacket Toolkit](active-directory/active-directory-toolkit/kali-linux-tools/impacket-toolkit.md)
    * [Bloodhound](active-directory/active-directory-toolkit/kali-linux-tools/bloodhound.md)
* [Enumerating Active Directory](active-directory/enumerating-active-directory/README.md)
  * [net.exe](active-directory/enumerating-active-directory/net.exe.md)
  * [Powershell Active Directory Commands](active-directory/enumerating-active-directory/powershell-active-directory-commands.md)
  * [Powershell & .NET Classes](active-directory/enumerating-active-directory/powershell-and-.net-classes.md)
  * [PowerView / SharpView](active-directory/enumerating-active-directory/powerview-sharpview.md)
  * [Enumerating Service Accounts](active-directory/enumerating-active-directory/enumerating-service-accounts.md)
  * [Enumerating Object Permissions](active-directory/enumerating-active-directory/enumerating-object-permissions.md)
  * [Enumerating Objects](active-directory/enumerating-active-directory/enumerating-objects.md)
  * [Active Directory Certificate Services (AD CS)](active-directory/enumerating-active-directory/active-directory-certificate-services-ad-cs.md)
* [Attacking Active Directory Authentication](active-directory/attacking-active-directory-authentication/README.md)
  * [AS-REP Roasting](active-directory/attacking-active-directory-authentication/as-rep-roasting.md)
  * [Kerberoasting](active-directory/attacking-active-directory-authentication/kerberoasting.md)
  * [Silver Tickets](active-directory/attacking-active-directory-authentication/silver-tickets.md)
  * [Domain Controller Synchronization (Dsync Attack)](active-directory/attacking-active-directory-authentication/domain-controller-synchronization-dsync-attack.md)
  * [Kerberos Relay Attack](active-directory/attacking-active-directory-authentication/kerberos-relay-attack.md)
  * [NTLM Relay Attack](active-directory/attacking-active-directory-authentication/ntlm-relay-attack.md)
  * [Attacking Service Accounts](active-directory/attacking-active-directory-authentication/attacking-service-accounts.md)
* [Password Spraying](active-directory/password-spraying/README.md)
  * [Enumeration & Retrieving Password Policy](active-directory/password-spraying/enumeration-and-retrieving-password-policy.md)
  * [Creating a Target User List](active-directory/password-spraying/creating-a-target-user-list.md)
  * [Brute Force / Password Spraying - Linux Tools](active-directory/password-spraying/brute-force-password-spraying-linux-tools.md)
  * [Internal Spraying - From Windows](active-directory/password-spraying/internal-spraying-from-windows.md)
* [Lateral Movement Techniques](active-directory/lateral-movement-techniques/README.md)
  * [WMI and WinRM](active-directory/lateral-movement-techniques/wmi-and-winrm.md)
  * [PsExec](active-directory/lateral-movement-techniques/psexec.md)
  * [Pass The Hash](active-directory/lateral-movement-techniques/pass-the-hash.md)
  * [Overpass The Hash](active-directory/lateral-movement-techniques/overpass-the-hash.md)
  * [Pass The Ticket](active-directory/lateral-movement-techniques/pass-the-ticket.md)
  * [DCOM](active-directory/lateral-movement-techniques/dcom.md)
* [Persistence](active-directory/persistence/README.md)
  * [Golden Ticket](active-directory/persistence/golden-ticket.md)
  * [Shadow Copies](active-directory/persistence/shadow-copies.md)
* [God Access](active-directory/god-access/README.md)
  * [GenericAll Abuse](active-directory/god-access/genericall-abuse.md)
  * [NTDS Tom Foolery](active-directory/god-access/ntds-tom-foolery.md)
* [Lab Environment Setup](active-directory/lab-environment-setup/README.md)
  * [Installing Forest](active-directory/lab-environment-setup/installing-forest.md)
  * [Adding Data to Active Directory](active-directory/lab-environment-setup/adding-data-to-active-directory.md)
* [Templates & Cheat Sheets](active-directory/templates-and-cheat-sheets.md)

## 🦈 Penetration Testing

* [Information Gathering / Reconnaisance](penetration-testing/information-gathering-reconnaisance/README.md)
  * [Client Fingerprinting](penetration-testing/information-gathering-reconnaisance/client-fingerprinting.md)
  * [External Recon and Enumeration](penetration-testing/information-gathering-reconnaisance/external-recon-and-enumeration.md)
  * [Network Reconnaisance](penetration-testing/information-gathering-reconnaisance/network-reconnaisance/README.md)
    * [Scanning for Hosts](penetration-testing/information-gathering-reconnaisance/network-reconnaisance/scanning-for-hosts.md)
    * [Initial Enumeration of AD Network](penetration-testing/information-gathering-reconnaisance/network-reconnaisance/initial-enumeration-of-ad-network.md)
    * [SMB Network Shares](penetration-testing/information-gathering-reconnaisance/network-reconnaisance/smb-network-shares.md)
  * [Vulnerability Scanning](penetration-testing/information-gathering-reconnaisance/vulnerability-scanning/README.md)
    * [Nessus](penetration-testing/information-gathering-reconnaisance/vulnerability-scanning/nessus.md)
    * [Nmap](penetration-testing/information-gathering-reconnaisance/vulnerability-scanning/nmap.md)
  * [Popped a Shell](penetration-testing/information-gathering-reconnaisance/popped-a-shell.md)
* [Pivoting, Tunneling, and Port Forwarding](penetration-testing/pivoting-tunneling-and-port-forwarding/README.md)
  * [SSH](penetration-testing/pivoting-tunneling-and-port-forwarding/ssh.md)
  * [Socat](penetration-testing/pivoting-tunneling-and-port-forwarding/socat.md)
  * [Pivoting ](penetration-testing/pivoting-tunneling-and-port-forwarding/pivoting/README.md)
    * [plink.exe](penetration-testing/pivoting-tunneling-and-port-forwarding/pivoting/plink.exe.md)
    * [netsh](penetration-testing/pivoting-tunneling-and-port-forwarding/pivoting/netsh.md)
    * [Web Server Pivoting with Rpivot](penetration-testing/pivoting-tunneling-and-port-forwarding/pivoting/web-server-pivoting-with-rpivot.md)
  * [Tunneling](penetration-testing/pivoting-tunneling-and-port-forwarding/tunneling/README.md)
    * [Chisel](penetration-testing/pivoting-tunneling-and-port-forwarding/tunneling/chisel.md)
    * [sshuttle](penetration-testing/pivoting-tunneling-and-port-forwarding/tunneling/sshuttle.md)
    * [Dnscat2](penetration-testing/pivoting-tunneling-and-port-forwarding/tunneling/dnscat2.md)
  * [Double Pivots](penetration-testing/pivoting-tunneling-and-port-forwarding/double-pivots/README.md)
    * [RDP and SOCKS Tunneling with SocksOverRDP](penetration-testing/pivoting-tunneling-and-port-forwarding/double-pivots/rdp-and-socks-tunneling-with-socksoverrdp.md)
* [Cracking Passwords](penetration-testing/cracking-passwords/README.md)
  * [Password Cracking Prerequisites](penetration-testing/cracking-passwords/password-cracking-prerequisites.md)
  * [Mutating Wordlists](penetration-testing/cracking-passwords/mutating-wordlists/README.md)
    * [Identifying & Building Rules](penetration-testing/cracking-passwords/mutating-wordlists/identifying-and-building-rules.md)
  * [Password Managers](penetration-testing/cracking-passwords/password-managers.md)
  * [SSH Private Keys](penetration-testing/cracking-passwords/ssh-private-keys.md)
  * [NTLM Toolkit](penetration-testing/cracking-passwords/ntlm-toolkit.md)
  * [NTLMv2](penetration-testing/cracking-passwords/ntlmv2.md)
  * [MS-Cachev2 (DCC2)](penetration-testing/cracking-passwords/ms-cachev2-dcc2.md)
  * [Password Protected Files](penetration-testing/cracking-passwords/password-protected-files.md)
* [Windows Privilege Escalation](penetration-testing/windows-privilege-escalation/README.md)
  * [Initial Enumeration](penetration-testing/windows-privilege-escalation/initial-enumeration.md)
  * [Searching For Sensitive Files](penetration-testing/windows-privilege-escalation/searching-for-sensitive-files.md)
  * [Searching Logs & Event Viewer](penetration-testing/windows-privilege-escalation/searching-logs-and-event-viewer.md)
  * [Escalating Privilege](penetration-testing/windows-privilege-escalation/escalating-privilege.md)
  * [Leveraging Windows Services](penetration-testing/windows-privilege-escalation/leveraging-windows-services/README.md)
    * [Service Binary Hijacking](penetration-testing/windows-privilege-escalation/leveraging-windows-services/service-binary-hijacking.md)
    * [Service DLL Hijacking](penetration-testing/windows-privilege-escalation/leveraging-windows-services/service-dll-hijacking.md)
    * [Abusing Unquoted Paths](penetration-testing/windows-privilege-escalation/leveraging-windows-services/abusing-unquoted-paths.md)
  * [Scheduled Tasks](penetration-testing/windows-privilege-escalation/scheduled-tasks.md)
  * [Enumerating Services & Tasks](penetration-testing/windows-privilege-escalation/enumerating-services-and-tasks.md)
  * [Dumping Secrets](penetration-testing/windows-privilege-escalation/dumping-secrets.md)
* [Linux Privilege Escalation](penetration-testing/linux-privilege-escalation/README.md)
  * [Initial Enumeration](penetration-testing/linux-privilege-escalation/initial-enumeration.md)
  * [Automated Enumeration](penetration-testing/linux-privilege-escalation/automated-enumeration.md)
  * [Searching For Sensitive Information](penetration-testing/linux-privilege-escalation/searching-for-sensitive-information.md)
  * [Insecure File Permissions](penetration-testing/linux-privilege-escalation/insecure-file-permissions.md)
  * [Insecure System Components](penetration-testing/linux-privilege-escalation/insecure-system-components/README.md)
    * [Abusing Setuid Binaries and Capabilities](penetration-testing/linux-privilege-escalation/insecure-system-components/abusing-setuid-binaries-and-capabilities.md)
    * [Sudo Trickery](penetration-testing/linux-privilege-escalation/insecure-system-components/sudo-trickery.md)
    * [Kernel Vulnerabilities](penetration-testing/linux-privilege-escalation/insecure-system-components/kernel-vulnerabilities.md)
  * [Abusing Environment Variables](penetration-testing/linux-privilege-escalation/abusing-environment-variables.md)
  * [Escaping Jail](penetration-testing/linux-privilege-escalation/escaping-jail.md)
  * [Wildcard Injection](penetration-testing/linux-privilege-escalation/wildcard-injection.md)
* [Exploiting Microsoft Office](penetration-testing/exploiting-microsoft-office/README.md)
  * [Phishing with Teams](penetration-testing/exploiting-microsoft-office/phishing-with-teams.md)
  * [Malicious Macros](penetration-testing/exploiting-microsoft-office/malicious-macros.md)
  * [Windows Library Files](penetration-testing/exploiting-microsoft-office/windows-library-files.md)
* [Setting up Infrastructure](penetration-testing/setting-up-infrastructure/README.md)
  * [C2 Infrastructure](penetration-testing/setting-up-infrastructure/c2-infrastructure.md)
  * [EvilGinx2 Phishing Infrastructure ](penetration-testing/setting-up-infrastructure/evilginx2-phishing-infrastructure.md)
* [Ex-filtrating Data](penetration-testing/ex-filtrating-data/README.md)
  * [WebDAV](penetration-testing/ex-filtrating-data/webdav.md)
  * [SMB](penetration-testing/ex-filtrating-data/smb.md)
  * [Converting files to Hex Strings](penetration-testing/ex-filtrating-data/converting-files-to-hex-strings.md)
* [Phishing](penetration-testing/phishing/README.md)
  * [OSCP Phishing Guide](penetration-testing/phishing/oscp-phishing-guide.md)
* [Templates & Cheat Sheets](penetration-testing/templates-and-cheat-sheets/README.md)
  * [OSCP Cheat Sheet](penetration-testing/templates-and-cheat-sheets/oscp-cheat-sheet.md)
  * [Impacket Cheat Sheet](penetration-testing/templates-and-cheat-sheets/impacket-cheat-sheet.md)
  * [Useful Commands](penetration-testing/templates-and-cheat-sheets/useful-commands.md)
  * [Penetration Test Checklist](penetration-testing/templates-and-cheat-sheets/penetration-test-checklist.md)

## 🛡️ Azure & M365

* [Information Gathering / Reconnaissance](azure-and-m365/information-gathering-reconnaissance/README.md)
  * [Domain Enumeration](azure-and-m365/information-gathering-reconnaissance/domain-enumeration.md)
  * [User Enumeration](azure-and-m365/information-gathering-reconnaissance/user-enumeration.md)
  * [AADInternals](azure-and-m365/information-gathering-reconnaissance/aadinternals.md)
* [Attacking Authentication](azure-and-m365/attacking-authentication/README.md)
  * [OWA Password Spraying](azure-and-m365/attacking-authentication/owa-password-spraying.md)
  * [OAuth Abuse](azure-and-m365/attacking-authentication/oauth-abuse.md)
* [Azure AD Killchain](azure-and-m365/azure-ad-killchain.md)
* [Azure Lab Setup](azure-and-m365/azure-lab-setup.md)
* [Azure & M365 Checklist](azure-and-m365/azure-and-m365-checklist.md)

## 🥾 Security Operation Center

* [Network Traffic Analysis](security-operation-center/network-traffic-analysis/README.md)
  * [Tcpdump](security-operation-center/network-traffic-analysis/tcpdump.md)
  * [Wireshark](security-operation-center/network-traffic-analysis/wireshark.md)
* [Windows Event Logs](security-operation-center/windows-event-logs/README.md)
  * [Sysmon](security-operation-center/windows-event-logs/sysmon.md)
* [Event Tracing for Windows (ETW)](security-operation-center/event-tracing-for-windows-etw.md)
* [Microsoft 365 Defender](security-operation-center/microsoft-365-defender.md)
* [Splunk as SIEM](security-operation-center/splunk-as-siem/README.md)
  * [Using Splunk Applications](security-operation-center/splunk-as-siem/using-splunk-applications.md)
  * [Search Processing Language (SPL) Commands](security-operation-center/splunk-as-siem/search-processing-language-spl-commands.md)
  * [Hunting with Splunk](security-operation-center/splunk-as-siem/hunting-with-splunk.md)
  * [Intrusion Detection](security-operation-center/splunk-as-siem/intrusion-detection.md)
* [Incident Response Process](security-operation-center/incident-response-process.md)
* [MITRE ATT\&CK Framework](security-operation-center/mitre-att-and-ck-framework/README.md)
  * [Persistence](security-operation-center/mitre-att-and-ck-framework/persistence/README.md)
    * [Registry Run Keys](security-operation-center/mitre-att-and-ck-framework/persistence/registry-run-keys.md)
* [Templates & Cheat Sheets](security-operation-center/templates-and-cheat-sheets/README.md)
  * [Interview Prep](security-operation-center/templates-and-cheat-sheets/interview-prep.md)

## 🔬 Digital Forensics

* [Tools](digital-forensics/tools.md)

## 🔍 Malware Analysis

* [Network Traffic Analysis](malware-analysis/network-traffic-analysis/README.md)
  * [INetSim](malware-analysis/network-traffic-analysis/inetsim.md)
* [Static Analysis](malware-analysis/static-analysis/README.md)
  * [Signatures & Fingerprints](malware-analysis/static-analysis/signatures-and-fingerprints.md)
  * [Pestudio](malware-analysis/static-analysis/pestudio.md)
  * [x64dbg](malware-analysis/static-analysis/x64dbg.md)
* [Dynamic Analysis](malware-analysis/dynamic-analysis/README.md)
  * [Noriben](malware-analysis/dynamic-analysis/noriben.md)
* [Reverse Engineering / Code Analysis](malware-analysis/reverse-engineering-code-analysis/README.md)
  * [IDA](malware-analysis/reverse-engineering-code-analysis/ida.md)
  * [x64dbg](malware-analysis/reverse-engineering-code-analysis/x64dbg.md)
  * [Returning Source Code](malware-analysis/reverse-engineering-code-analysis/returning-source-code/README.md)
    * [.NET Binary](malware-analysis/reverse-engineering-code-analysis/returning-source-code/.net-binary.md)
* [Creating Detection Rules](malware-analysis/creating-detection-rules.md)
* [Tools](malware-analysis/tools.md)

## 🛠️ Programming

* [MASM Assembly ](programming/masm-assembly.md)
* [Qt](programming/qt/README.md)
  * [Setting up Qt in CLion](programming/qt/setting-up-qt-in-clion.md)
* [Windows Development on MacOS](programming/windows-development-on-macos/README.md)
  * [CLion Setup](programming/windows-development-on-macos/clion-setup.md)
* [Windows Driver Development](programming/windows-driver-development/README.md)
  * [Installing Windows SDK & WDK](programming/windows-driver-development/installing-windows-sdk-and-wdk.md)
* [Windows API](programming/windows-api/README.md)
  * [Deleting Files](programming/windows-api/deleting-files.md)
  * [Strings](programming/windows-api/strings.md)
  * [wininet.h](programming/windows-api/wininet.h.md)
  * [Wrapping WinAPI Functions](programming/windows-api/wrapping-winapi-functions.md)
  * [code\_seg](programming/windows-api/code_seg.md)
  * [Locating WinAPI Functions - Tips ](programming/windows-api/locating-winapi-functions-tips.md)
* [Visual Studio](programming/visual-studio/README.md)
  * [Creating DLL's](programming/visual-studio/creating-dlls.md)
  * [Debug & Release Mode](programming/visual-studio/debug-and-release-mode.md)
* [Mingw](programming/mingw/README.md)
  * [Windows Development](programming/mingw/windows-development.md)
* [Position Independent Code (PIC)](programming/position-independent-code-pic/README.md)
  * [Creating Shellcode](programming/position-independent-code-pic/creating-shellcode.md)
  * [Debugging & Development Tips](programming/position-independent-code-pic/debugging-and-development-tips.md)
  * [Strings](programming/position-independent-code-pic/strings.md)
  * [Macros](programming/position-independent-code-pic/macros.md)
  * [PIC Checklist](programming/position-independent-code-pic/pic-checklist.md)

## 🏠 Home Lab

* [Current Setup](home-lab/current-setup.md)
