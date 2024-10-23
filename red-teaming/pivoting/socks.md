# SOCKS



## Cobalt Strike

Cobalt Strike has both a **SOCKS4a** and **SOCKS5** proxy.  SOCKS5 supports authentication.

### Running Socks

Use the `socks` command on the Beacon that you want to act as the pivot host.

```sh
// SOCKS4
beacon> socks 1080
// SOCKS5:
beacon> socks 1080 socks5 disableNoAuth user password enableLogging
```

<mark style="color:red;">**Note**</mark>: The speed at which SOCKS transmits data is determined by the beacon sleep time. \
