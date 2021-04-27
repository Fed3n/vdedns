# VDEDNS

## An Internet of Threads enabled DNS proxy for the resolution of IPv6 hash addresses

VdeDNS is a DNS proxy whose main objective is to enable the resolution of [Hash based IPv6 Addresses](http://wiki.virtualsquare.org/#!ideas/hashipv6.md) and [One Time IP Addresses](http://wiki.virtualsquare.org/#!ideas/otip.md). The user can configure the proxy to solve specific domains and subdomains according to the specifics of the aforementioned special addresses, using either locally set domain,base-address pairs or forwarding the request for a base-address of a domain to a master DNS. All other DNS requests to non-configured domains are forwarded directly to a master DNS with no additional parsing. VdeDNS is fully asynchronous and poll based, supporting both UDP and TCP DNS requests.

VdeDNS can run as a regular proxy DNS on port 53 of the kernel networking stack (and so requiring CAP_NET_ADMIN rights). Being [IoTh](http://wiki.virtualsquare.org/#!tutorials/ioth.md) enabled, it can also be ran completely or partially on a virtual networking stack (so requiring no special permissions) created at process level making use of the [libioth](https://github.com/virtualsquare/libioth/) library API. The meaning of "partially" is that the proxy can open the accepting socket and the request forwarding socket on two different networking stacks (e.g. accepting socket on a virtual network stack and forwarding socket on kernel stack), offering the possibility for more flexibility and security.


