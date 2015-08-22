#!/bin/sh

# A "proxy-layer" both listens and forwards to the next immediate "proxy-layer"
# (you may have multiple "proxy-layer"s, as in complex layer-7 architecture)
../subsegment_speeds_v2_tornado.py -l localhost:9090 -f localhost:9091 --debug 7
