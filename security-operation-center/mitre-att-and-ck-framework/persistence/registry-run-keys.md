# Registry Run Keys



## Introduction&#x20;

The goal with registry run keys is to quickly establish permissions and persistence on a system. By adding a run key to the start up folder, that process will run everytime an authenticated user logs in.

Note: Startup folders are different for both local-user and system-level accounts.

## What is the Windows Registry?

The registry is a file system that stores application settings, low-level system settings, and user preferences.&#x20;



## Registry Structure

* Hives: Contain keys (directories) and values.
* Keys: May contain subkeys and/or values.
* Subkeys: no difference between keys. Just a sub structure of a key.
* Values: Stores the data associated with it's key.

## Registry Root Keys:

| Root Key                           | Description                                                                                                                                                                                                                                                                       |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| <p>HKCR<br>(HKEY_CLASSES_ROOT)</p> | Describes file type, file extensions, and OLE Information                                                                                                                                                                                                                         |
| <p>HKCU<br>(HKEY_CURRENT_USER)</p> | Contains user who is currently logged in to Windows and their settings.                                                                                                                                                                                                           |
| <p>HKU<br>(HKEY_LOCAL_MACHINE)</p> | Contains computer-specific information about the hardware installed, software settings, and other information. The information is used for all users who log on to the computer. This key is one of the most frequent areas of the registry that is viewed and editited by users. |
| <p>HKU<br>(HKEY_LOCAL_MACHINE)</p> | Contains infomration about all the users who log on to the computer. Both generic and user-specific information.                                                                                                                                                                  |
| <p>HKCC<br>HKEY_CURRENT_CONFIG</p> | The details about the current configuration of hardware attached to the computer.                                                                                                                                                                                                 |
| <p>HKDD<br>(HKEY_DYN_DATA)</p>     | Only used in Windows 95, 98, and NT. Contains dynamic plug and play information.                                                                                                                                                                                                  |

##

## What is a Registry Run Key?

Registry Run Keys cause programs to run each time a user logs on. Threat actors often create a Run key so that their code will persist once a user logs in again.

The simpler two tactics is using the Windows startup folder located at:

### **C:\Users\\\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup.**

* Shortcut links (.link extension) placed in this folder will cause Windows to launch the application each time \<username> logs in. This is used by various forms of malware.



### The registry run keys perform the same action, but can be located in the four different locations:

* HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\Run
* HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
* HKEY\_LOCAL\_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
* HKEY\_LOCAL\_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

The difference between HKEY\_CURRENT\_USER & HKEY\_LOCAL\_MACHINE is whether the executable launches for EVERY user that logs in or just a specific user.

Run and RunOnce; the only difference is that RunOnce will automatically delete the entry upon successful execution.



### The following registry run keys can be used to set startup folders items for persistence:

Placing a malicious file under the startup directories is often used by malware authors.

* HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
* HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
* HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
* HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders



### The following registry keys can control automatic startup of services on boot:

* HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
* HKEY\_LOCAL\_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
* HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
* HKEY\_LOCAL\_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices

## Common Attack workflow:

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>



## Detection and Mitigation

In order to have proper visibilty and effective detections the following must be in place:

* Command-line logging.
* FIM (File Integrity Monitoring) or a tool like SysInterals to detect file-level changes.
* Windows Security Events (ETW).
* Network Logging

