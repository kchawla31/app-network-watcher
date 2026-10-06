# App Network Watcher protocol

The desktop app and the Android companion share these messages. Neither side sends captured bodies anywhere but the local proxy.

## QR setup

```
watcher://connect?host=<host>&port=<port>&fp=<sha256-fingerprint>
```

`fp` is the SHA-256 fingerprint of the CA certificate DER, uppercase hex bytes separated by colons. `host` is an address the phone can reach. With ADB reverse that address is `127.0.0.1` on the device. The QR fallback uses this computer's LAN address, and the proxy listens on every interface so that address works.

## ADB launch

```
adb -s <serial> reverse tcp:<port> tcp:<port>
adb -s <serial> push <ca.cer> /sdcard/Download/app-network-watcher-ca.crt
adb -s <serial> shell am start -n com.appnetworkwatcher/.MainActivity \
  --es host 127.0.0.1 --ei port <port> --es fp <fingerprint>
```

The desktop does not treat interception as started until logcat tag `WatcherVpn` contains both `VPN_READY` and `CERT_APPROVED`. After that it runs:

```
adb -s <serial> shell settings put global http_proxy 127.0.0.1:<port>
```

`VPN_READY` is logged only after `VpnService.Builder.establish()` returns a tunnel. `CERT_APPROVED` is logged when the person checks that they approved the certificate prompt. `CERT_PROMPT_SHOWN` means the install intent was opened. `VPN_DENIED` means the person dismissed the VPN dialog.

## What the VPN captures

The companion address is `10.7.0.1/32`. It routes IPv4 `0.0.0.0/0`. On Android 10 and newer the VPN also sets the process HTTP proxy to the desktop.

TCP ports 80, 443, 8000, 8001, 8080, 8888, and 9000 are sent to the proxy:

- Port 80 is rewritten to an absolute-form HTTP request and written to the proxy.
- Other intercepted ports use `CONNECT <host>:<port>` after the companion reads SNI, or the HTTP `Host` header when there is no SNI. The hostname is what the MITM certificate is issued for.
- A connection whose destination is already the proxy is forwarded on a protected socket, so `adb reverse` does not loop back into the VPN.

Other IPv4 TCP ports and UDP datagrams are forwarded on protected sockets and are not decrypted. IPv6 is not captured. ICMP is not relayed. The relay does not retransmit lost TCP segments.

## Certificate trust

Android 7 and newer ignore a user CA unless the app trusts user CAs.

- `base-config` with `src="user"` trusts this CA in debug and release builds of an app you ship.
- `debug-overrides` trusts it only while the app is debuggable.
- A system-store copy runs only after the desktop confirmation is ticked, and only for an emulator or a device where `adb root` already yields `uid=0`. The desktop does not try to root a device.

Apps that pin certificates fail the TLS handshake. The capture log says so. There is no pinning bypass.

## HTTP version

The proxy offers HTTP/2 to the client when the setting is Auto or HTTP/2. Bytes toward the origin are HTTP/1.1. TLS passthrough hosts skip MITM and are dialed directly, not through the upstream proxy.
