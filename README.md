# subsegment_tcp_speeds-l7

# WIP

This project is a *work in progress*. The implementation is *incomplete* and subject to change. The documentation can be inaccurate.

# Description

In time-sensitive networks, to find which network subsegment has the highest increase in TCP delay (similar to tcptraceroute but higher in the protocol-stack and not using the IP TTL field, because when the TTL expires, this condition is handled immediately in kernel mode)

This is similar in idea (although this program works on raw TCP) to what HAProxy can do in HTTP under a time-sensitive network with:

        haproxy.cfg:
                ...
                http-request add-header "X-my-http-header-timeStamp-at-Proxy"  "%ms"
                # (or better,  http-request add-header "X-my-http-header-timeStamp-at-Proxy"  "%f %ms" )

        Or Squid in a reverse-proxy situation with:

                squid.conf:
                       ...
                       request_header_add  X-my-http-header-timeStamp-at-Proxy  "%tS"

where "%ms" is the timestamp in milliseconds when this HTTP header is added by the HTTP proxy ( for internals, see http://git.haproxy.org/?p=haproxy-1.5.git;a=blob;f=src/log.c;hb=HEAD#l1140 about the usage of "%ms"). (Disclaimer: the current python program is not at the HTTP level as HAProxy can be, but at the TCP level, and it is inspired by that idea in HAProxy, but does not utilize that code). (So far, HAProxy allows those custom values, as "%ms", in custom http-headers; nginx will have it soon: http://wiki.nginx.org/HttpHeadersMoreModule#TODO )

This project is similar in idea too to what the Akamai Content Delivery Network (CDN)
does with this request ( click here: http://time.akamai.com/?xml )

       $ curl http://time.akamai.com/?xml ; echo

          .... <rtt>2</rtt>...

where it prints the RTT in this segment, whose extremes are the `curl` client or browser
and the `time.akamai.com` server, although this project finds the RTT delays in multiple
segments (as those found in multiple layers of proxies, load balancers, etc). (The
documentation for the Akamai feature can be found here:

     https://developer.akamai.com/stuff/Akamai_Time_Reference/AkamaiTimeReference.html

)

Custom http headers for the time at each processing host can be similar to the `Via:` http header, where each intermediate host stamps itself in this header (by appending to the Via-value, not by adding more http headers). E.g., this `Via:` value:

        Via: 1.1 v1-akamaitech.net(ghost) (AkamaiGHost), 1.1 akamai.net(ghost) (AkamaiGHost), 1.1 cach06 (squid/3.5.1)

        http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.45

# Requeriments

You need to install the Python `Tornado` module:

     pip install tornado

or

     easy_install tornado

# Usage:

Program for helping to isolate which sub-segment in a network [or proxy host in a network] influences more in the delay of a network transmission.

Formally, it works as chain of network proxies with send measure headers among each proxy in the chain.

     Invocation:

          subsegment_layer7_speeds.py   [-{l|-listen} <listen-addr>]
                                        [-{f|-forward_to} <forward_to-address>]
                                        [-{d|-debug} <debug-level>]
                                        [-{n|-dont-add-perf-headers}]
                                        [-{t|-add-static-tags} <static-annotations>]

     Command-line arguments:

          -{d|-debug} <debug-level>:     debug level (0: emerg ... 7: debug)


          -{l|-listen} <listen-addr>:    which TCP address:port to listen for
                                         incoming packets. (default: none)

                                        If this option -{l|-listen} is not used,
                                        the program will read from the
                                        standard-input as fast as possible,
                                        inserting performance-headers every
                                        -{b|-block} bytes of read-data; the
                                        answered-data, in turn, will be printed
                                        to std-output.


          -{f|-forward_to} <forward_to-address>:       to which TCP address:port
                                                       to forward the input data
                                                       (default: none)

                                        The input data forwarded is the one read
                                        either by the -{l|-listen} address, or
                                        by standard-input if the -{l|-listen}
                                        address is omitted.

                                        If -{f|-forward_to} is omitted, then
                                        there will be no forwarding, and this
                                        command invocation will echo-back to the
                                        -{l|-listen} address whatever it
                                        receives from it.


          -{n|-dont-add-perf-headers}:     Whether to add or not the dynamic
                                           performance headers belonging to
                                           this hop in the packets (default:
                                           add them)

          -{t|-add-static-tags}:     Static tags (headers) with which to
                                     annotate the incoming packets (these tags
                                     are not computed dynamically by the
                                     program, they are just enumerared in the
                                     command-line)


# Example:

In the `examples` subdirectory of this project there is a simple set of wrappers
to be used around this script.

A more general case with four layers of hosts making up the chain of communication
sub-segments in the network, the client layer `A` works with (connects to) next layer 
`B`, `B` to hops in layer `C`, and `C` to the backend layer `Z`. Layer `B` can be in
another co-location or geographically remote in comparison to `A`, or be an entry
point with heavy-load to another network, etc. The same applies with `C` in comparison
to `B`, it can be in another co-location or geographically remote in comparison to
`C`, etc; and so on in this delay-sensitive computer network: annotations can help to
distinguish which `instance` in which `layer` the network packet has passed through:

           source host in layer A:

                    subsegment_layer7_speeds.py  --forward_to  <layer-B>:9000 \
                                                 --add-static-tags `hostname`

                        In this case, A forwards its standard-input to the
                        proxies at layer B, and gets its answer (and
                        time-delay stats) from B. Besides, it also adds a
                        static header, the `hostname` of the source host at
                        this layer A.

           intermediate host in proxy layer B:

                    subsegment_layer7_speeds.py  --listen  '*:9000'  \
                                                 --forward_to  <host-C>:9000 \
                                                 --add-static-tags `hostname`

                        In this case, B forwards its standard-input to the
                        proxies at layer C, and gets its answer (and time-delay
                        stats) from C. Besides, it also adds a static header,
                        the `hostname` of the hop in this layer B that
                        forwarded the packet.

           intermediate host in proxy layer C:

                    subsegment_layer7_speeds.py  --listen  '*:9000' \
                                                 --forward_to  <host-Z>:9000 \
                                                 --add-static-tags `hostname`

                        In this case, layer C forwards its incoming packets to
                        the layer Z, and gets its answer (and time-delay stats)
                        from Z.

           end host in backend layer Z:

                    subsegment_layer7_speeds.py  --listen  '*:9000' \
                                                 --add-static-tags `hostname`

                        In this case, Z doesn't use a --forward_to option, so
                        it is the end backend which resolves client A's initial
                        request. This script simply echoes back the initial
                        request, so it answers A's standard-input back to A
                        (and time-delay stats and static-tags)."""


# Practical use:

A utility like this can be integrated under a `monitoring and/or graphing system`
to receive the annotations of a packet along each proxy (processing hop) in a
path of proxies A<->B<->C...<->Z, so it can graph and alert when the annotations
on the delays on any subsegment happens to be out of the SLA parameters (for
that subsegment).

The difference between a utility like this and `traceroute`, is that `traceroute`
operates usually at the kernel level when the kernel answers with an `ICMP TTL
exceeded` (except when the random port `traceroute` uses is open, in which case
the packet does passes to user-land), and this utility works in user-mode only,
so it is easier for it to suffer from, and reflect, high CPU load in its host,
than the internal TCP/IP stack inside the kernel. Secondly, a utility like this
offers more potentiality for annotating in the processed packets more variables
along the path it visits than is possible with `traceroute`, like to record many
of the hop's `SNMP MIB` variables (e.g., CPU load in the last 1, 5, and 15
minutes, etc). In this sense, a utility like this can not only isolate the
subsegment that is having delays, but directly try to investigate into the why
such subsegment happens to be outside its expected SLA range, and for this it
can conditionally query and annotate some SNMP MIB variables in it only when
that unexpected situation happens, following a playbook according to the
subsegment with issues and to how much the deviation from its SLA happens to be.
Finally, in open networks between different companies, `traceroute` doesn't need
to traverse, in general, a pre-established set of hops A, B, C, ..., Z, unless
the `IP loose-source-routing` option is set in the request (and honored by
intermediate routers between those companies), which `IP loose-source-routing`
option also complicates the `TTL-expire` adjustment by `traceroute`, e.g., in
the case of dynamic, or self-organizing, networks.

# Other tools and methods:

Another way is to `wrap` scriptable code which encapsulates the request to the server
and to pass this `wrapping` code into the server to measure the timing from the server
perspective, and then to compare that server-side timing with the client-side timing.
In this case, the server does not serve `specific requests`, but is in certain way an
`application server` which receives and executes the `remote scripts` submitted to it,
giving to this script `an application library and environment` in a sandbox. Ie., the
project:

    https://github.com/je-nunez/timing_Redis_queries_with_embedded_LUA

is an example of this submission of a `Lua` wrapper around a `GET` query into the `Redis`
server, which acts as an `application server` in this case giving the `redis.call()`
and `redis.pcall()` `application library and environment` to the incoming Lua script (plus
others, like `redis.log()`, etc). (The difference between this project and the Redis/Lua
one is that this second one doesn't allow to return back `harmless` annotations about
performance `in extra fields` together with the answer, `harmless` in the sense that they
don't affect the main answer, which in general Redis doesn't allow us to do -unless the
specific cached value in Redis happened to be a `JSON` object and the `Lua` script embeds
the annotations about server-side performance in the answer as extra JSON fields through
its `cjson` library, or we add the performance annotations in the answer through
[deeply nested multi bulk replies in the Redis protocol] (http://redis.io/topics/protocol "multi bulk reply"),
or similarly, the client understands and expects the `MessagePack` binary encoding and
the embedded wrapper uses the Lua `cmsgpack` Lua library the Redis application server
makes available to the script.)

`nginx` and `PowerDns`, among others, are also other examples of such `application
servers` which allow embedding (also of `Lua`, although not receiving remote Lua
scripts from the clients to execute, for security reasons.)

Tools most known in lower-level layers in the protocol stack are `ping`, `traceroute`
(and similar, like `tcptraceroute`, etc).

The `TCP header` itself usually has a timestamp option (`RFC 1323`) which is used
for Round-Trip Time Measurement, as well as `IP header` may have several timestamps,
as the utility in this project (`RFC 781` and `RFC 791`):

    Timestamp in header:

      TCP header:  https://tools.ietf.org/html/rfc1323#section-3

      IP header:   https://tools.ietf.org/html/rfc781
                   https://tools.ietf.org/html/rfc791 (chaining of several timestamps)

The issue with these timestamps in the headers of the lower layers is that they
are not passed to user-mode applications, so to obtain them you need to use the
`libpcap` (or equivalent) library, and that their timestamp is not in epoch time
-even under synchronization by NTP in the network, but the relative `uptime` of
the host, so two hosts A and B won't have the same timestamps unless they were boot
up at exactly the same time, and to solve this, two packets or more have to be
transmitted between hosts A and B to find the deltas of the timestamps between those
two packets. (See, eg., in Linux:
				
      /proc/sys/net/ipv4/tcp_timestamps
				
and the use of this TCP timestamp in `./<linux-kernel>/net/ipv4/tcp_output.c`,
which takes its value from the kernel `jiffies` since the boot
(`./<linux-kernel>/include/net/tcp.h`)).

`ICMP` also has an option to request the Timestamp (ICMP type 13) and to reply it
(ICMP type 14) (`RFC 1349`, section 5.1):

     https://tools.ietf.org/html/rfc1349#section-5.1

See, eg., `nmap` option `-PP` to send an ICMP Timestamp request.

A different approach is the `IP Flow Information Export` protocol, where the routers
and switches send flow information outband (see `RFCs 7011 and 7015`). This idea is
used, eg., in Linux, by the `conntrackd` daemon and the `conntrack` command-line
program can do statistics gathering.

