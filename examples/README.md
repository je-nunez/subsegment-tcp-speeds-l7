# Simple examples of measuring at layer 7

# WIP

This project is a *work in progress*. The implementation is *incomplete* and subject to change. The documentation can be inaccurate.

# Description

These are a set of small wrappers intended to be used at the same time. They
simply call the main program in its different roles (the `original client`,
`intermediate layers of proxies` -in this case only one intermediate layer
of proxies-, and finally a layer of `backend servers`):

      wrapper_original_client.sh        uses option "--forward_to ..." alone

      wrapper_proxy_layer_number_1.sh   uses both options "--listen ..." and 
                                        "--forward_to ..."

      wrapper_final_backend_server.sh   uses option "--listen ..." alone

In all cases, the invocation of the main program is with `--debug 7`, which
asks the program to dump the annotations inside the packets as they travel
through each layer-7 hop, and not merely prints the summary of the final
measures.

# See also

The ![README](../README.md?raw=true "README") of the main project has more
details.
