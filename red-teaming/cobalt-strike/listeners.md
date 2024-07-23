# Listeners



## Introduction

Cobalt Strike has two listeners: egress listeners and peer-to-peer listeners. Egress listeners are for external connections outside of the network. Facilitation occurs either through HTTP or DNS. Peer-to-Peer (P2) listeners to do not communicate with the team server directory like egress listeners, instead, they combine multiple Beacons together in parent/child relationships. The reasons for this is simple: it reduces the number of hosts talking to the team server (which reduces traffic volume and likelihood of getting burned). It also allows machines who cant talk outside the network to communicate through this type of proxy system. P2P listeners can use SMB or TCP. The traffic from the P2P is sent to the parent who transmits it to the team server.

## Egress Listeners

Egress listeners are for external connections outside of the network (HTTP or DNS).

### HTTP Listener

Communication occurs over HTTP GET & POST requests.

To add a new listener: Click headphones -> Add -> Input details & Save

<figure><img src="../../.gitbook/assets/Screenshot 2024-07-23 at 2.31.52 PM.png" alt=""><figcaption></figcaption></figure>

### DNS Listener

DNS listeners allows Beacons to send messages over several lookup types A, AAAA, TXT. To use DNS listeners, we must configure our DNS records. For example:

| <p>Name<br></p> | <p>Type<br></p> | <p>Data<br></p>      |
| --------------- | --------------- | -------------------- |
| @               | A               | \<DNS Resolver>      |
| <p>ns1<br></p>  | <p>A<br></p>    | \<DNS Resolver>      |
| img             | <p>NS<br></p>   | ns1.copperwired.com. |

Creating listener

<figure><img src="../../.gitbook/assets/Screenshot 2024-07-23 at 2.39.42 PM (1).png" alt="" width="375"><figcaption></figcaption></figure>

We now have two listeners:

<figure><img src="../../.gitbook/assets/Screenshot 2024-07-23 at 2.40.30 PM.png" alt=""><figcaption></figcaption></figure>



## P2P Listeners

Peer (P2) listeners to do not communicate with the team server directory like egress listeners, instead, they combine multiple Beacons together in parent/child relationships.&#x20;

* This reduces the number of hosts talking to the team server (which reduces traffic volume and likelihood of getting burned).
* It also allows machines who cant talk outside the network to communicate through this type of proxy system. P2P listeners can use SMB or TCP. The traffic from the P2P is sent to the parent who transmits it to the team server.

### SMB Listener

For SMB listeners, the default named pipe is not going to work. We can list named pipes on the host with the following command. We'll change the last couple numbers to something recognizable.

```powershell
PS> ls \\.\.pipe\
```

<figure><img src="../../.gitbook/assets/Screenshot 2024-07-23 at 3.14.04 PM.png" alt="" width="375"><figcaption></figcaption></figure>



### TCP Listener

Your typical TCP listener. Nothing special.

<figure><img src="../../.gitbook/assets/Screenshot 2024-07-23 at 3.17.37 PM.png" alt="" width="375"><figcaption></figcaption></figure>



We now have all our listeners!

<figure><img src="../../.gitbook/assets/Screenshot 2024-07-23 at 3.17.56 PM.png" alt=""><figcaption></figcaption></figure>



## Pivot Listener

Setting up a listener for pivoting is different than default listeners. Pivot listeners can only be created through a beacon.&#x20;



To create a pivot listener right-click on the Beacon and go Pivoting -> Listener -> "Open Listener".

<figure><img src="../../.gitbook/assets/Screenshot 2024-07-23 at 4.11.27 PM.png" alt="" width="375"><figcaption></figcaption></figure>

Confirming the port is listening and notice the process ID. It's the same as our Beacon PID.

```
beacon> run netstat -anop tcp

Active Connections

  Proto  Local Address          Foreign Address        State           PID

  TCP    0.0.0.0:4444           0.0.0.0:0              LISTENING       2280
```



You can run `spawn` in the beacon promt selected a pivot listener. Optionally, you can create one. The Beacon commands`elevate`, and `jump` can also be used for pivoting.

<figure><img src="../../.gitbook/assets/Screenshot 2024-07-23 at 4.18.25 PM.png" alt=""><figcaption></figcaption></figure>

Unfortunately, with Defender enabled, we get burned. We'll have to put some work into our Payload to go undetected.

<figure><img src="../../.gitbook/assets/Screenshot 2024-07-23 at 4.18.50 PM.png" alt=""><figcaption></figcaption></figure>
