# VDEDNS

## iothnamed
VdeDNS was part of my bachelor thesis project and it was written while being advised by professor Renzo Davoli for his [Virtualsquare](http://wiki.virtualsquare.org/#!index.md) laboratory.
It was eventually rewritten in its current version [iothnamed](https://github.com/virtualsquare/iothnamed), so please use that one instead if you are looking for a DNS solution for the IoTh!

## An Internet of Threads enabled DNS proxy for the resolution of IPv6 hash addresses

VdeDNS is a DNS proxy whose main objective is to enable the resolution of [Hash based IPv6 Addresses](http://wiki.virtualsquare.org/#!ideas/hashipv6.md) and [One Time IP Addresses](http://wiki.virtualsquare.org/#!ideas/otip.md). The user can configure the proxy to solve specific domains and subdomains according to the specifics of the aforementioned special addresses, using either locally set domain,base-address pairs or forwarding the request for a base-address of a domain to a master DNS. All other DNS requests to non-configured domains are forwarded directly to a master DNS with no additional parsing. VdeDNS is fully asynchronous and poll based, supporting both UDP and TCP DNS requests.

VdeDNS can run as a regular proxy DNS on port 53 of the kernel networking stack (and so requiring CAP_NET_ADMIN rights). Being [IoTh](http://wiki.virtualsquare.org/#!tutorials/ioth.md) enabled, it can also be ran completely or partially on a virtual networking stack (so requiring no special permissions) created at process level making use of the [libioth](https://github.com/virtualsquare/libioth/) library API. The meaning of "partially" is that the proxy can open the accepting socket and the request forwarding socket on two different networking stacks (e.g. accepting socket on a virtual network stack and forwarding socket on kernel stack), offering the possibility for more flexibility and security.


## Install

### Pre-Requisites:
- [`libioth`](https://github.com/virtualsquare/libioth)
- [`iothaddr`](https://github.com/virtualsquare/libioth)
- [`iothdns`](https://github.com/virtualsquare/iothdns)
- [`iothconf`](https://github.com/virtualsquare/iothconf)
- [`libconfig`](http://hyperrealm.github.io/libconfig)

`vdedns` compiles and installs using cmake. Standard procedure is:

```bash
mkdir build
cd build
cmake ..
make
sudo make install
```

To uninstall files, run:
```bash
sudo make uninstall
```

## Configuration

`vdedns` requires a libconfig-format configuration file to run. 
Default installation path of a basic configuration file is /usr/local/etc/vdedns.cfg (a basic configuration file is there provided at installation).
When `vdedns` is run as superuser (so pretty much whenever it is ran on the kernel networking stack) it will fetch the configuration file from the default path, else it expects a configuration file in ~/.config/vdedns.cfg.
A custom path can be passed as an argument at launch.

All possibile aspects of the configuration and its fields follow:

### DNS Servers

The *dns_servers* field takes comma separated IPv4 or IPv6 addresses which will 
be queried in succession for forwarded DNS queries.

    dns_servers = (
        "10.9.8.7",
        "abcd:ef00::",
        "1.2.3.4"
    );

### Domains

The *domains* field is divided in *hash* (hash based addresses) and *otip* (one time ip addresses).

Hash addresses are taken as comma separated domain names.
A query to a base domain configured as an hash domain (i.e. mydomain.org) still returns
an unchanged base address. A query to a subdomain of an hash domain instead returns an
hashed address (i.e. hash.mydomain.org).
If a configured hash domain is a subdomain of another configured one, when parsing a query
the longest matching one takes priority.

OTIP addresses are taken as objects made of mandatory *dom*, *pswd* and optional *time* fields.
The *dom* field is as above the OTIP domain name, the *pswd* field is the domain access password
and *time* is the address duration. This last field is optional, if not specified default
address duration is 32 seconds.

    domains = {
        hash = (
            "myhashdomain.org",
            "hash.domain.org",
            "another.hash.domain.org"
        );
        otip = (
            {
                dom="default.otip.org";
                pswd="password";
            },
            {
                dom="longer.otip.org";
                pswd="secret";
                time=128;
            }
        );
    };

### Addresses

The *addresses* field is a list of local domains,addresses objects which `vdedns` will 
prioritize when solving queries before forwarding.
Each object is made of a mandatory *dom* field and at least one between a *ip4*
or *ip6* field.
The *dom* field is as before a domain name, the *ip4* and *ip6* fields are a list of
comma separated addresses.

    addresses = (
        {
            dom="hash.domain.org";
            ip6=("2001:aaaa::12");
        },
        {
            dom="owndomain.mine";
            ip4=("42.41.40.39", "127.0.42.1");
            ip6=("fc00:ffff:dddd::");
        }
    );

### Virtual interfaces

The *vinterface* field sets which parts of `vdedns` to virtualize and how 
when using the `--stacks` option.
If *both* field is set, then both the accepting socket stack and querying socket stack use
this same configuration. Otherwise the *dns* field specifies the stack to use for the accepting
socket stack and the *query* field specifies the stack to use for the querying socket stack.
Inside the stack field *type* is the virtual networking stack to use (e.g. *vdestack*), 
the *vnl* is which virtual network locator should the stack be created on and *config* is an
`iothconf` configuration string. 
Please refer to `libioth` and `Virtual Distributed Ethernet` documentation 
for virtual networking stacks configuration.
    
    vinterface = {
        both = {
            type="vdestack";
            vnl="vde://";
            config="eth,ip=10.0.0.1/24,ip=fc00:aaaa::1/64,gw=10.0.0.254,fqdn=my.vdedns";
        };
    };

### Authorization

The *authorization* field takes address, address mask pairs to decide which addresses
should be authorized to submit queries to `vdedns` when using the `--auth` option.
The *ip* field takes an ip address and the *mask* field takes a same address type mask.

    authorization = (
        {
            ip="127.0.0.1";
            mask="255.255.255.255";
        },
        {
            ip="10.0.0.0";
            mask="255.255.255.0";
        },
        {
            ip="2001:abcd:ef00::";
            mask="ffff:ffff:ffff:ffff::"
        }
    );

## Usage

Run `vdedns` as superuser to let it bind on port 53, unless you are binding it on a virtual networking stack.
DNS requests will need to be redirected to the address `vdedns` is running on (e.g. editing /etc/resolv.conf on most unix-like systems to add `nameserver address` on top).

If running as a local proxy, you should either block external DNS requests to your machine or simply bind `vdedns` to the loopback address running it as `sudo vdedns -b 127.0.0.1` .

If you are often running `vdedns`, you should probably run it as a daemon saving logs to the log file.
In this case run it as `sudo vdedns -d -L` .

`vdedns` has many more options, including UDP buffer size customization to enable compatibility with DNS extensions.
The man page should cover each possible option.
