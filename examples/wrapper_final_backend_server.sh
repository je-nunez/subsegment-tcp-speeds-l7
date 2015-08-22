#!/bin/sh

# The "final-backend-server" only listens but does not forward
../subsegment_speeds_v2_tornado.py -l localhost:9091 --debug 7
