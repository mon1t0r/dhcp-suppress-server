## Overview
This project is an implementation of a simple DHCP server, which supresses
other DHCP servers in a network to send its own parameters.

The application listens for any broadcast and unicast DHCP traffic and replies
to the following messages:
 - DHCPDISCOVER: send DHCPOFFER with configured parameters;
 - DHCPREQUEST: if target server is the application server, send DHCPACK with
 configured parameters, otherwise send DHCPNAK. DHCPNAK is sent with the IP of
 requested (other in network) server, and MAC is also set, if the appropriate
 IP:MAC pair is found in application's MAC table.

Application MAC table is filled when DHCPOFFER message is received from any
other DHCP server in network.

Currently the application DHCP server is only sending broadcast DHCP messages.

The system works the best in networks, where latency from potential client to
the original DHCP server is higher, than to the application DHCP server, as
typically DHCP client implementations will accept first DHCP offer they
receive.

## Build and run
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
sudo release/dhcp_server [OPTION]... [MY_ADDR] [MY_MAC]
```

### Options
```
MY_ADDR - network address, which will be used as the application DHCP server own address
MY_MAC  - MAC address, which will be used as the application DHCP server own address

-I --interface              interface name
-S --server-port            port number for DHCP requests
-C --client-port            port number for DHCP responses
-s --mac-table-size         MAC table size (entry count is not limited to
                            this number; this number only indicates the number
                            of cells, which will be allocated to MAC hashtable)
-t --mac-table-max-cnt      MAC table max entry count (actual limit for MAC
                            table entries; when the limit is reached, table is
                            cleared)
-i --conf-client-addr       DHCP configuration (yiaddr)  - client address
-b --conf-broadcast-addr    DHCP configuration (opt. 28) - network broadcast address
-m --conf-subnet-mask       DHCP configuration (opt. 1)  - subnet mask
-r --conf-router-addr       DHCP configuration (opt. 3)  - router address
-d --conf-dns-addr          DHCP configuration (opt. 6)  - DNS address
-a --conf-time-address      DHCP configuration (opt. 51) - address lease time
-n --conf-time-renewal      DHCP configuration (opt. 58) - address renewal time
-e --conf-time-rebinding    DHCP configuration (opt. 59) - address rebinding time
```

## TODO
 - implement option to manually set initial entries for MAC table.
