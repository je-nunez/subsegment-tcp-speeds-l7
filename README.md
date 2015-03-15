# subsegment-tcp-speeds-l7
In time-sensitive networks, to find which network subsegment has the highest increase in TCP delay (similar to tcptraceroute but higher in the protocol-stack and not using the IP TTL field, because when the TTL expires, this condition is handled immediately in kernel mode)

This is similar in idea (although this program is raw TCP) to what HAProxy can do with its instruction:

	http-request add-header "X-my-header-timeStamp-at-Proxy"  "%ms"
        (or better,  http-request add-header "X-my-header-timeStamp-at-Proxy"  "%f %ms" )

where "%ts" is the timestamp in milliseconds when this HTTP header is added by the HTTP proxy HAProxy ( for internals, see http://git.haproxy.org/?p=haproxy-1.5.git;a=blob;f=src/log.c;hb=HEAD#l1140 about the usage of "%ms"). (Disclaimer: this program is not at the HTTP level, but at the TCP level, and it is inspired by that possibility, but does not utilize that code). (So far, HAProxy allows those custom values, as "%ms", in custom http-headers; nginx will have it soon: http://wiki.nginx.org/HttpHeadersMoreModule#TODO )

Usage: Program for helping to isolate which sub-segment in a network [or proxy host in a network] influences more in the delay of a network transmission.

Formally, it works as chain of network proxies with send measure headers among each proxy in the chain.

Invocation:
     subsegment-tcp-speeds.py  [-{t|timeout} <timeout>]  [-{l|listen} <listen-addr>]  [-{f|forward-to} <forward-to-address>]  [-{r|remove-perf-headers}]

     Command-line arguments:

          -{t|timeout} <timeout>:       specify the timeout for each operation (default: 10 seconds)

          -{l|listen} <listen-addr>:    which TCP address:port to listen for incoming packets (default: none)

                                        If this option -{l|listen} is not used, the program will read from the standard-input as fast as possible,
                                        inserting performance-headers every -{b|block} bytes of read-data; the answered-data, in turn, will be printed to stardard-output.


          -{f|forward-to} <forward-to-address>:         to which TCP address:port to forward the input data (default: none)
                                        The input data forwarded is the one read either by the -{l|listen} address, or by standard-input if the -{l|listen} address is omitted.

                                        If -{f|forward-to} is omitted, then there will be no forwarding, and this command invocation will echo-back to the -{l|listen} address
                                        whatever it receives from it.


          -{r|remove-perf-headers}:     whether to remove or not existing performance headers in a packet (default: do not remove performance headers in a packet)

Example:
      This is an example with four hosts making up the chain of sub-segments in the network, A<->B, B<->C, C<->D:

           source host A:

           intermediate host B:

           intermediate host C:

           end host Z:



