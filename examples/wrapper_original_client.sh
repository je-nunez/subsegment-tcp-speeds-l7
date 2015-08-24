#!/bin/sh

# The "original-client" only forwards its standard input to the first pooled
# layer of proxies (which are listening at the TCP address:port given by
# the option '-f ...')
#
# Warning: Long-Lines below for static-tags (explicit static-headers)
./subsegment_layer7_speeds.py -f localhost:9090 --debug 7 \
                   --add-static-tags `hostname` \
--add-static-tags "This is a host sending its standard-input from the initial layer of senders"
