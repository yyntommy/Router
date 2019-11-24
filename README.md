# Router


First Part: Built is a router with a static routing table. The router will
receive raw Ethernet frames. It will process the packets just like a real router, and
forward them to the correct outgoing interface. The router supports pinging, tracerouting, and downloading a file using HTTP.

Then improved the router by implementing a dynamic routing protocol, RIP, so that
the router can generate its forwarding table automatically based on routes advertised by
other routers on the network,
