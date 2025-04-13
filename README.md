## Overview
This project is an implementation of a simple DHCP server, which supresses other DHCP servers in
a network to send its own parameters.

The application listens for any broadcast and unicast DHCP traffic and replies to the following
messages:
 - DHCPDISCOVER: send DHCPOFFER with configured parameters;
 - DHCPREQUEST: if target server is the application server, send DHCPACK with configured parameters,
   otherwise send DHCPNAK with sender IP and MAC address of the other server.

Currently the application DHCP server is only sending broadcast DHCP messages.

The system works the best in networks, where latency from potential client to the real DHCP server is higher, than to
the application DHCP server, as typically DHCP client implementations will accept first DHCP offer they receive.

## Build from source
### Requirements
```
gcc
make
cppcheck
```

### Build
```
git clone https://github.com/mon1t0r/dhcp-suppress-server
cd dhcp-suppress-server
make
```

### Run
```
sudo ./dhcp_server
```

## TODO
 - implement work in networks with more than one DHCP server:
   send DHCPNAK with dynamic IP and MAC address of the other server;
 - configuration from command line arguments/config file.
