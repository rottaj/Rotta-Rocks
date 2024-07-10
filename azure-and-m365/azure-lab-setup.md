# Azure Lab Setup



## Introduction

For our Azure environment we will create the following things:

### Creating Azure Tenants

**Create M365 Business Basic**

[https://www.microsoft.com/en-us/microsoft-365/business#layout-container-uid4d2d](https://www.microsoft.com/en-us/microsoft-365/business#layout-container-uid4d2d)

**Free Entra ID Tenant with $200 USD License**\
[https://azure.microsoft.com/en-us/free/entra-id](https://azure.microsoft.com/en-us/free/entra-id)

**Create E3 License**\
[https://admin.microsoft.com/](https://admin.microsoft.com/)

**Purview Trial**\
[https://compliance.microsoft.com/](https://compliance.microsoft.com/)

**Create E3 M365 License**\
[https://learn.microsoft.com/en-gb/purview/compliance-easy-trials](https://learn.microsoft.com/en-gb/purview/compliance-easy-trials)





### Create an M365 Business Account

In order to access admin.microsoft.com, we'll need to have a business account. This will give us access to all Microsoft Office applications. Purchase the Basic account.

[https://www.microsoft.com/en-us/microsoft-365/business#layout-container-uid4d2d](https://www.microsoft.com/en-us/microsoft-365/business#layout-container-uid4d2d)

### Create an Azure Account

It's recommended to purchase a new domain and register an email with it as we'll be able utilize Microsofts free Azure 12 month trial for newly registered accounts. You may want to go grab a prepaid SIM card as well because you'll need to provide a phone number that isn't registered to an existing M365 account. Once everything is ready to go, continue with the steps below.

**Free Entra ID Tenant with $200 USD License**\
[https://azure.microsoft.com/en-us/free/entra-id](https://azure.microsoft.com/en-us/free/entra-id)

### Create Users

We'll create a global admin user along with 2-3 regular users for this lab environment.

Navigate to portal.azure.com -> Microsoft Entra ID

<figure><img src="../.gitbook/assets/Screenshot 2024-07-09 at 9.30.53 AM.png" alt=""><figcaption></figcaption></figure>

Click User -> Create new user

<figure><img src="../.gitbook/assets/Screenshot 2024-07-09 at 9.32.48 AM.png" alt=""><figcaption></figcaption></figure>

Assign user to Global Administrator

<figure><img src="../.gitbook/assets/Screenshot 2024-07-09 at 9.37.14 AM.png" alt=""><figcaption></figcaption></figure>

Create two more regular users

<figure><img src="../.gitbook/assets/Screenshot 2024-07-09 at 9.46.30 AM.png" alt=""><figcaption></figcaption></figure>

We now should have one Global Administrator & two regular users.





### Create E3 License

Next we want to register for an E3 License. This may take up to 3 business days for the registration to complete.

{% embed url="https://admin.microsoft.com/" %}

<figure><img src="../.gitbook/assets/Screenshot 2024-07-09 at 12.06.24 PM.png" alt=""><figcaption></figcaption></figure>

Go to the catalog under products and search "E3".

### Assign E3 License

After purchases our Office 365 E3 License, go back to our azure portal (portal.azure.com) and assign the license to a user. We can do so by searching "Licenses" > "All Products" > "Assign".

<figure><img src="../.gitbook/assets/Screenshot 2024-07-09 at 12.13.53 PM.png" alt=""><figcaption></figcaption></figure>

After assigning the license to a user we should see our updated licensed user.

<figure><img src="../.gitbook/assets/Screenshot 2024-07-09 at 12.16.59 PM.png" alt=""><figcaption></figcaption></figure>

### Activate Purview Trial

Navigate to compliance.microsoft.com and click "Trials". <mark style="color:red;">**NOTE**</mark>: You'll have to wait 3-5 business days to activate this trial.

<figure><img src="../.gitbook/assets/Screenshot 2024-07-09 at 12.24.40 PM.png" alt=""><figcaption></figcaption></figure>

