# NTLM Relay Attacks

## Introduction

NTLM authentication uses a three way handshake when verifying a clients credentials.

* <mark style="color:yellow;">First</mark>: The client makes a request to a server for a resource it wishes to access.
* <mark style="color:yellow;">Second</mark>: The server sends a challenge to the client, which the client then encrypts the challenge using the hash of their password.
* <mark style="color:yellow;">Third</mark>: The client sends the encrypted response back to the server, which then contacts the domain controller to verify the encrypted challenge is correct.&#x20;

NTLM relaying allows us to intercept this traffic and impersonate the client.

<mark style="color:red;">**Note**</mark>: NTLM relaying for on-premise penetration testing can be found under "Active Directory" -> Attacking Authentication -> [NTLM Relay](https://www.rotta.rocks/active-directory/attacking-active-directory-authentication/ntlm-relay-attack).

## NTLM Relay - Cobalt Strike

In order to perform an NTLM relay attack using Cobalt Strike we will need the following:

* [WinDivert](https://reqrypt.org/windivert.html) driver to redirect traffic from port 445 externally (e.g. 8445)
* A [reverse port forward](https://www.rotta.rocks/red-teaming/proxies-pivoting-and-port-forwarding/reverse-port-forwarding) on the port the SMB traffic is being redirected to (e.g 8445).
* A tool like [Responder](https://github.com/lgandx/Responder) and [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/tree/master/impacket/examples/ntlmrelayx).
* A SOCKS proxy to allow ntlmrelayx or Responder to send traffic back into the target network.

