# Interview Prep

### OSI Model

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

### 5 Main Registry Hives

* [HKEY\_CLASSES\_ROOT](https://learn.microsoft.com/en-us/windows/win32/sysinfo/hkey-classes-root-key)&#x20;
* [HKEY\_CURRENT\_USER](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users).
* [HKEY\_LOCAL\_MACHINE](https://www.lifewire.com/hkey-local-machine-2625902).
* [HKEY\_USERS](https://www.lifewire.com/hkey-users-2625903).
* [HKEY\_CURRENT\_CONFIG](https://www.lifewire.com/hkey-current-config-2625900).



### Security Operation Model (SOC Lifecycle)

* Tier 1: Triage
* Tier 2: Investigate
* Tier 3: Hunt

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>



##

## MITRE ATT\&CK Framework

### Scheduled Task Protection & Mitigation

* Configure OS to force scheduled tasks to only run under the authenticated users instead of system accounts. This is done by editing the HKLM/SYSTEM registry key. For orgs, this can be configured globally through the GPO for all workstations.
* Set the GPO to only allow admins to schedule tasks.



### Registry Run Keys Protection & Mitigation

An adversaries goal with registry run keys is to quickly establish permissions and persistence on a system. By adding a registry run key to the startup folder, the process will launch everytime an authenticated user logs in.

**Note:** There are startup folders for both local and system-level accounts.

