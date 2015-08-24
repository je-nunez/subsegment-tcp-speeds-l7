#!/bin/sh

# The "final-backend-server" only listens but does not forward
#
# Warning: Long-Lines below for static-tags (explicit static-headers)
./subsegment_layer7_speeds.py -l localhost:9091 --debug 7 \
                      --add-static-tags `hostname` \
--add-static-tags "This is a host receiving in the layer of final backends"
