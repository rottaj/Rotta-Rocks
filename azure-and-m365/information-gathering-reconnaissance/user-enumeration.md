# User Enumeration



### Hunting for Guest

When sharing SharePoint to people outside the organization or inviting them to Teams, a corresponding guest account is created to Azure AD. Although the created guest account is not a pure insider, it has wide read-only access to organization's Azure AD information. The blog I'm referencing can be found [here](https://aadinternals.com/post/quest\_for\_guest/).

Here is a list of [default user & guest permissions](https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#compare-member-and-guest-default-permissions) within AAD.

### Generating a user list

