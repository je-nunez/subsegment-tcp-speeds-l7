# Simple examples of measuring at layer 7

# WIP

This project is a *work in progress*. The implementation is *incomplete* and subject to change. The documentation can be inaccurate.

# Description

These are a set of small wrappers intended to be used at the same time. They
simply call the main program in its different roles (the `original client`,
`intermediate layers of proxies` -in this case only one intermediate layer
of proxies-, and finally a layer of `backend servers`):

      wrapper_original_client.sh          uses option "--forward_to ..." alone

      wrapper_proxy_layer_number_1.sh     uses both options "--listen ..." and 
                                          "--forward_to ..."

      wrapper_final_backend_server.sh     uses option "--listen ..." alone

An example output, after some lines have been input into the `original client`, is:

      <-- Delay between 127_0_0_1_64840 and localhost_9090 = 496 microsecs
      <-- Delay between stdin and localhost_9090 = 969 microsecs
      ...
      < Line: .... my line # 1 ...
      ...
      ...
      <-- Delay between 127_0_0_1_64840 and localhost_9090 = 470 microsecs
      <-- Delay between stdin and localhost_9090 = 980 microsecs
      ...
      < Line: .... my line # 2 ...
      ...

so it is giving the delays (in microseconds) between each layer-7 in the
communication chain. (This output sample above does not mention other
annotations and other information offered by `static-tags` and `debug`
options -see below- which are independent to the dynamic annotations in
the packets computed by the program.)

In all cases, the invocation of the main program is with `--debug 7`, which
asks the program to dump the annotations inside the packets as they travel
through each layer-7 hop, and not merely prints the summary of the final
measures.

Besides, these examples also use the `--add-static-tags $( hostname )`
to insert a static annotation inside the packet identifying which specific
instance among the several instances in a pooled layer processed the packet,
plus other `--add-static-tags "any-static-annotation-string"` options.
(These static annotations are given at the command-line and are different
than the dynamic annotations inserted into a packet, which are computed
inside the program.)

# See also

The ![README](../README.md "README") of the main project has more details.

