# subsegment-tcp-speeds-l7

In time-sensitive networks, to find which network subsegment has the highest increase in TCP delay (similar to tcptraceroute but higher in the protocol-stack and not using the IP TTL field, because when the TTL expires, this condition is handled immediately in kernel mode)

This is similar in idea (although this program works on raw TCP) to what HAProxy can do in HTTP under a time-sensitive network with:

        haproxy.cfg:
                ...
                http-request add-header "X-my-http-header-timeStamp-at-Proxy"  "%ms"
                # (or better,  http-request add-header "X-my-http-header-timeStamp-at-Proxy"  "%f %ms" )

where "%ms" is the timestamp in milliseconds when this HTTP header is added by the HTTP proxy ( for internals, see http://git.haproxy.org/?p=haproxy-1.5.git;a=blob;f=src/log.c;hb=HEAD#l1140 about the usage of "%ms"). (Disclaimer: the current python program is not at the HTTP level as HAProxy can be, but at the TCP level, and it is inspired by that idea in HAProxy, but does not utilize that code). (So far, HAProxy allows those custom values, as "%ms", in custom http-headers; nginx will have it soon: http://wiki.nginx.org/HttpHeadersMoreModule#TODO )

Usage: 

Program for helping to isolate which sub-segment in a network [or proxy host in a network] influences more in the delay of a network transmission.

Formally, it works as chain of network proxies with send measure headers among each proxy in the chain.

     Invocation:
     
          subsegment-tcp-speeds.py  [-{t|-timeout} <timeout>]  [-{l|-listen} <listen-addr>]  [-{f|-forward-to} <forward-to-address>]  -{s|-stdin-block-size} <std-in-block-size>   [-{r|-remove-perf-headers}]
     
     Command-line arguments:
     
          -{t|-timeout} <timeout>:       specify the timeout for each operation (default: 10 seconds)
     
     
          -{l|-listen} <listen-addr>:    which TCP address:port to listen for incoming packets.
                                         (default: none)
     
                                        If this option -{l|-listen} is not used, the program will 
                                        read from the standard-input as fast as possible, inserting 
                                        performance-headers every -{b|-block} bytes of read-data;
                                        the answered-data, in turn, will be printed to stardard-output.
     
     
          -{f|-forward-to} <forward-to-address>:         to which TCP address:port to forward the
                                                         input data (default: none)
                                        The input data forwarded is the one read either by the 
                                        -{l|-listen} address, or by standard-input if the 
                                        -{l|-listen} address is omitted.
     
                                        If -{f|-forward-to} is omitted, then there will be no 
                                        forwarding, and this command invocation will echo-back to the 
                                        -{l|-listen} address whatever it receives from it.
     
     
          -{s|-stdin-block-size} <std-in-block-size>:    Standard-input block size in bytes 
                                                         (default: 512)

                                        If -{l|-listen} is not used, the program will read from 
                                        standard-input using the block-size indicated here. These 
                                        blocks so read are the ones that are then forwarded from 
                                        this program to the next subsegment in the network (if
                                        there is one), or to stdout (if there are no -{f|-forward-to}
                                        address).
     
     
          -{r|-remove-perf-headers}:     whether to remove or not existing performance headers in a 
                                         packet (default: do not remove performance headers in a packet)
     

Example:

      This is an example with four hosts making up the chain of communication sub-segments in the 
      network, the client A works with (connects to) B, B to C, and C to Z. B can be in another 
      co-location or geographically remote in comparison to A, or be an entry point with heavy-load 
      to another network, etc. The same applies with C in comparison to B, it can be in another 
      co-location or geographically remote in comparison to C, etc; and so on in this 
      time-sensitive computer network.
           
           source host A:

                    subsegment-tcp-speeds.py  --forward-to  <host-B>:9000  
                    
                        In this case, A forwards its standard-input to the proxy at B, and gets 
                        its answer (and time-delay stats) from B. 

           intermediate host B:

                    subsegment-tcp-speeds.py  --listen  '*:9000'  --forward-to  <host-C>:9000  
                    
                        In this case, B forwards its standard-input to the proxy at C, and gets 
                        its answer (and time-delay stats) from C.

           intermediate host C:

                    subsegment-tcp-speeds.py  --listen  '*:9000'  --forward-to  <host-Z>:9000  
                    
                        In this case, C forwards its standard-input to the proxy at Z, and gets 
                        its answer (and time-delay stats) from Z.

           end host Z:

                    subsegment-tcp-speeds.py  --listen  <host-B>:9000  

                        In this case, Z doesn't use a --forward-to option, so it is the end 
                        backend which resolves client A's initial request. This script simply 
                        echoes back the initial request, so it sends back A's standard-input 
                        back to A (and time-delay stats).

