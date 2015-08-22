#!/bin/sh

# The "original-client" only forwards to the first pooled layer of proxies
../subsegment_speeds_v2_tornado.py -f localhost:9090 --debug 7
