#!/bin/sh

# A "proxy-layer" both listens with the option "-l <address:tcp-port>" and
# forwards to the next immediate "proxy-layer" at "-f <address:tcp-port>"
# (you may have multiple "proxy-layer"s, as in a complex layer-7 architecture)
#
# Warning: Long-Lines below for static-tags (explicit static-headers)
./subsegment_speeds_v2_tornado.py -l localhost:9090 -f localhost:9091 \
                       --debug 7 --add-static-tags `hostname` \
--add-static-tags "This is a host receiving and forwarding in the first layer of proxies"
