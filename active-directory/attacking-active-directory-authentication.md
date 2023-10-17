# Attacking Active Directory Authentication

Microsoft Active Directory (AD) supports several authentication protocols, each with its own use case and role in the authentication process. Here is a list of some common authentication protocols in Active Directory, in the order of default and fallback:

1. **Kerberos Authentication**
   * **Used For**: Primary authentication method in Windows environments.
   * **When Used**: Used for initial user authentication when a user logs in. It provides strong security and is the default choice for Active Directory.
   * Relies on DNS, and the use of the Domain Controller in the role of a _Key Distribution Center_ (KDC)
   * Ticketing System
2. **NTLM (NT LAN Manager)**
   * **Used For**: Legacy authentication protocol.
   * **When Used**: When Kerberos is unavailable. When a client authenticates with an IP address rather than a host name, or if the user attempts to authenticate to a hostname that is not registered on the Active Directory DNS system.
   * Challenge and Response Paradigm.
3. **Digest Authentication**
   * **Used For**: HTTP-based authentication, often used for web services and applications.
   * **When Used**: Used in scenarios where the client and server need to authenticate each other over HTTP.
   *
4. **Certificate-Based Authentication (Smart Cards)**
   * **Used For**: Secure authentication using smart cards.
   * **When Used**: Utilized when organizations require highly secure authentication mechanisms, such as government agencies or financial institutions.
   *
5. **LDAP (Lightweight Directory Access Protocol)**
   * **Used For**: Directory services queries, not typically for user authentication.
   * **When Used**: Used by applications and services to query Active Directory for information.
   * **Default/Fallback**: Not used for user authentication but for querying directory information.
6. **RADIUS (Remote Authentication Dial-In User Service)**
   * **Used For**: Authentication for remote access (e.g., VPN, dial-up).
   * **When Used**: Mainly used for remote user access authentication, often in conjunction with Network Policy Server (NPS).
   * Used when remote access scenarios are involved, not the primary for on-premises user login.
7. **Azure Active Directory (Azure AD) Authentication**
   * **Used For**: Cloud-based authentication and identity management.
   * **When Used**: For integrating cloud services, applications, and identity management with on-premises Active Directory.
   * Used in hybrid environments to extend AD authentication to Azure services.
