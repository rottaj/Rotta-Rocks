# Kerberos & Active Directory Attacks

## Introduction

### Kerberos Authentication:

#### AS-REQ

When a user logs onto their workstation, their machine will send an AS-REQ message to the Key Distribution Center (KDC) (Domain Controller). This message requests a TGT using a secret key derived from the user's password.

#### AS-REP

The KDC verifies the secret key with the password is has stored in Active Directory for that user, it returns a TGT as a AS-REP message. The TGT contains the user's identity and is encryted with the KDC secret key (the **krbtgt** account).

### Accessing Resources:

#### TGS-REQ

When a user attempts to access a resource backed by Kerberos authentication, their machine looks up the associated Service Prinical Name (SPN). It then requests a Ticket Granting Service Ticket (TGS) in the form a TGS-REQ. It presents the user's TGT as a way of providing they're a valid user.

#### TGS-REP

The KDC returns a TGS (TGS-REP) for the service in question, which is then presented to the actual service. The service inspects the TGS and decides wheter it should grant access.
