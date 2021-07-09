# vdedns setup example and explanation

vdedns needs a configuration file to enable its basic functions.
The program at startup will look for such file in the */etc/vdedns.cfg* path by default when run as superuser or in the *~/config/vdedns.cfg* path when run as user.
vdedns can still be obviously run with a configuration file from a path of choice by using the `--config` (or `-c`) flag followed by a file path.

A sample starting configuration file should have been given along with vdedns.
Following, another similar example file will be written and commented step by step.

## Forwarding resolutions

vdedns is a non-recursive proxy DNS and as such forwards requests not found in its local.
First of all, vdedns should be set as the only system DNS to prevent queries answers directly from other remote servers.
On most unix-like systems, add the `nameserver 127.0.0.1` line on top of the */etc/resolv.conf* file, comment all the other ones and you should be set.

Starting with an empty configuration file, let's try running vdedns.
```
echo > tutorial.cfg
sudo vdedns -v 3 -c tutorial.cfg
```
vdedns should have given a warning that no master DNS is set and will not forward requests.
When vdedns is not forwarding requests it will return a domain not found response every time the query is not found in its local records.

So if you now try running `host kernel.org` you should get a NXDOMAIN response.

Let's add a couple master DNS addresses to the configuration file *tutorial.cfg*, in the **dns_servers** field.
```
dns_servers = (
    "1.1.1.1",
    "80.80.80.80"
);
```
Now running vdedns as before should give no warning and running `host debian.org` should give a valid resolution.

vdedns takes more than one master DNS server as a fallback mechanism: if a forwarded query times out (default is 1 second), vdedns will query the next DNS server, if it exists.
Let's try adding a bad DNS server changing the configuration as:
```
dns_servers = (
    //obviously assuming 10.9.8.7 is not a valid DNS server
    "10.9.8.7",
    "1.1.1.1",
    "80.80.80.80"
);
```
And then run (the `--timeout` or `-t` option takes milliseconds as a parameter):
```
vdedns -v 3 -c tutorial.cfg -t 3000
```
Trying to run `host debian.org` should take 3 seconds per requested record, as the first bad DNS does not answer within 3 seconds.

Having too low of a timeout will prevent forwarded requests resolution, as every DNS server will be discarded too soon.
The bad master DNS should be removed from the configuration file going forward.

## Adding HASH and OTIP rules

The heart of vdedns is the resolution of the special IPv6 HASH/OTIP addresses.
Such resolutions are triggered by the **rules** field containing the **hash** and **otip** subfields.
vdedns will try solving any domain listed there as the corresponding type, answering with only IPv6 AAAA records.

For this section vdedns can always be run as:
```
vdedns -v 3 -c tutorial.cfg
```

Before updating the configuration file, running `host debian.org` and `host gnu.org` will return their corresponding regular records.
Let's try adding those as hash and otip domains, adding to the *tutorial.cfg* configuration file:
```
rules = {
    hash = (
        "debian.org"
    );
    otip = (
        {
            dom="gnu.org";
            pswd="free";
            time=8;
        }
    );
};
```

Running `host debian.org` will now return only IPv6 addresses, but the correct ones being the domain at the top of the hierarchy.
Running `host sub.debian.org` (or any other *debian.org* subdomain) will instead return the previous base address hashed with the full domain name.
Once a hash resolution for a certain domain has occurred, vdedns will store it for a certain amount of time (default is 1 hour, can be changed with the `--revtimeout` or `-R` flag) and will be able to solve it in reverse, so trying to solve one of the previous results with `host` should return the original domain.

Running `host gnu.org` will now return temporary IPv6 addresses, which are going to change every 8 seconds.
OTIP-only addresses are not cached for reverse resolution and do not match with subdomains.

One domain can be in both the **hash** and **otip** fields, in this case it will be solved as an OTIP address but also allowing subdomain matching.


## Local records

vdedns allows the solving of local A and AAAA records set in the configuration file.
Let's try adding some local records using the **records** field in our *tutorial.cfg* configuration file:
```
records = (
    {
        dom="hashdomain.vde";
        ip6=("fc00:4242::17");
    },
    {
        dom="otipdomain.vde";
        ip6=("fc00:4242::13");
    },
    {
        dom="vdednstest.vde";
        ip4=(
            "10.9.8.7",
            "11.12.13.14"
        );
        ip6=(
            "fc00:a987::1",
            "fc00:4242::beef"    
        );
    }
);
```
Running vdedns exactly as seen before, `host hashdomain.vde`, `host otipdomain.vde` and `host vdednstest.vde` should now give an answer.
As can be seen in the *vdednstest.vde* domain, multiple addresses can be added as a list in a comma-separated format.

vdedns can obviously solve both local and non-local records as HASH/OTIP, so the previous **rules** configuration can be modified as:
```
rules = {
    hash = (
        "debian.org",
        "hashdomain.vde"
    );
    otip = (
        {
            dom="gnu.org";
            pswd="free";
            time=8;
        },
        {
            dom="otipdomain.vde";
            pswd="secret";
            time=32;
        }
    );
};
```
So that *hashdomain.vde* and *otipdomain.vde* will be solved as HASH and OTIP addresses respectively.

## Set up vdedns as an IoTh process

vdedns can be run on its own virtual networking stack by launching with the `--stacks` or `-s` option.
In detail, the program can separately run on two different stacks, one for clients listening and the other for forwarding queries.
The configuration allows for vdedns to run both functionalities fully on kernel stack, on a single virtual stack, two separate virtual stacks, or one virtual stack and one kernel stack.

To run vdedns on a single virtual stack for both listening and querying, add to the **vinterface** field in *tutorial.cfg*:
```
vinterface = {
    both = {
        type="vdestack";
        vnl="vxvde://234.0.0.1";
        config="eth,ip=10.0.0.1/24,gw=10.0.0.254,fqdn=local.dns.fwd";
    };
};
```
Where *type* is the stack library to use, *vnl* is the VDE virtual network locator and *config* is an *iothconf* string (see https://github.com/virtualsquare/iothconf ).

To test the above configuration, you can setup your system executing as root:
```
ip tuntap add mode tap tap0;
ip addr add 10.0.0.254/24 dev tap0;
ip link set tap0 up;
echo '1' > /proc/sys/net/ipv4/ip_forward;
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE;
```
Substituting *eth0* with your Internet connected networking interface.
This will also enable forwarding through your Internet connected interface.

And then run as user, to be able to connect to the IoTh stack:
```
vde_plug tap://tap0 vxvde://234.0.0.1
```

Now launch vdedns as:
```
vdedns -c tutorial.cfg -v 3 -s
```
And set your system DNS server to 10.0.0.1 as we did before.
Notice how vdedns now does not need to be run as superuser, as it will not bind on the kernel stack and so won't be needing any special permission.

To handle single stacks, comment or remove the **both** field and use either or both the **dns** and **query** fields:
```
vinterface = {
/*
    both = {
        type="vdestack";
        vnl="vxvde://234.0.0.1";
        config="eth,ip=10.0.0.1/24,gw=10.0.0.254,fqdn=local.dns.fwd";
  };
*/
    dns = {
        type="vdestack";
        vnl="vxvde://234.0.0.1";
        config="eth,ip=10.0.0.1/24,gw=10.0.0.254,fqdn=local.dns.fwd";
    }; 
    query = {
        type="vdestack";
        vnl="vxvde://234.0.0.1";
        config="eth,ip=10.0.0.2/24,gw=10.0.0.254,fqdn=local.dns.query"; 
    };
};

```
In the above example, DNS queries will be accepted at the 10.0.0.1 address and request forwarding will happen through the 10.0.0.2 address.

Any unhandled field when using the *--stacks* or *-s* option will be bound on the kernel stack.
The **both** field always takes priority regardless of order.

## Set authorized addresses

vdedns comes with the option to restrict the DNS usage to only some IP addresses by launching with the `--auth` or `-a` option.
Such authorized addresses are set in the configuration file specifying a base address and a netmask.

If we try to launch vdedns with usage restrictions without setting up any authorized address:
```
vdedns -v 3 -c tutorial.cfg -a
```
Any valid DNS query will be answered with a REFUSED response.

Let's now add an **authorization** field to *tutorial.cfg*:
```
authorization = (
    {
        ip="192.168.0.0";
        mask="255.255.0.0";
    },
    {
        ip="127.0.0.0";
        mask="255.255.255.0";
    },
    {
        ip="fe80::";
        mask="ffff::";
    }
);
```
Now vdedns should answer local queries once again when launching the same as above.

## Final configuration file
```
dns_servers = (
    "1.1.1.1",
    "80.80.80.80"
);

rules = {
    hash = (
        "debian.org",
        "hashdomain.vde"
    );
    otip = (
        {
            dom="gnu.org";
            pswd="free";
            time=8;
        },
        {
            dom="otipdomain.vde";
            pswd="secret";
            time=32;
        }
    );
};

records = (
    {
        dom="hashdomain.vde";
        ip6=("fc00:4242::17");
    },
    {
        dom="otipdomain.vde";
        ip6=("fc00:4242::13");
    },
    {
        dom="vdednstest.vde";
        ip4=(
            "10.9.8.7",
            "11.12.13.14"
        );
        ip6=(
            "fc00:a987::1",
            "fc00:4242::beef"    
        );
    }
);

vinterface = {
    both = {
        type="vdestack";
        vnl="vxvde://234.0.0.1";
        config="eth,ip=10.0.0.1/24,gw=10.0.0.254,fqdn=local.dns.fwd";
  };
    dns = {
        type="vdestack";
        vnl="vxvde://234.0.0.1";
        config="eth,ip=10.0.0.1/24,gw=10.0.0.254,fqdn=local.dns.fwd";
    }; 
    query = {
        type="vdestack";
        vnl="vxvde://234.0.0.1";
        config="eth,ip=10.0.0.2/24,gw=10.0.0.254,fqdn=local.dns.query"; 
    };
};

authorization = (
    {
        ip="192.168.0.0";
        mask="255.255.0.0";
    },
    {
        ip="127.0.0.0";
        mask="255.255.255.0";
    },
    {
        ip="fe80::";
        mask="ffff::";
    }
);
```
