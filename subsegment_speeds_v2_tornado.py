#!/usr/bin/env python
#
# Modified from:
#     https://pypi.python.org/pypi/quickproxy/0.2.0
# that is a Tornado HTTPproxy in the PyPi repo (but this script is a TCP proxy)
#
import sys
import os
import argparse
from argparse import RawDescriptionHelpFormatter
import inspect
import time
# import dateutil.parser
# from copy import copy
import socket
import re
import random

import itertools
import tornado.ioloop
import tornado.iostream
import tornado.escape
import tornado.tcpclient
import tornado.tcpserver

"""
class tornado.tcpclient.TCPClient(resolver=None)
      A non-blocking TCP connection factory.

      connect(*args, **kwargs)
      Connect to the given host and port.

      Asynchronously returns an IOStream (or SSLIOStream if ssl_options is not None).


class tornado.tcpserver.TCPServer(io_loop=None, ssl_options=None, max_buffer_size=None, read_chunk_size=None)
"""

# The hostname of this proxy
my_host_domain_name = ""


class EstablishedListener(object):
    """
        Per-connection object.
    """

    def __init__(self, stream, client_addr, local_addr, forwarding_dest):
        self.client_stream = stream
        stream.set_close_callback(self.on_disconnect)
        stream.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        stream.socket.setsockopt(socket.IPPROTO_TCP, socket.SO_KEEPALIVE, 1)

        self.client_addr = client_addr  # the client which connect()-ed to us
        self.local_addr = local_addr    # our proxy listening address
        self.forwarding_destination = forwarding_dest # where to forward to
        self.forw_stream = None         # the stream connected to forward to

        # generate a unique UUID with which to annotate the lines in this
        # connection with the timestamps (ie., this is the annotation cookie)
        my_field_listen_addr = re.sub(r"[^a-zA-Z0-9]", "_", local_addr)
        my_field_client_addr = re.sub(r"[^a-zA-Z0-9]", "_", client_addr)

        my_salt = random.randint(0,10000000)
        json_tstamp_fieldname_uuid = "X_My_Annotation_%s_%s_%d" % \
                                   (my_field_listen_addr, my_field_client_addr,
                                    my_salt)
        # TODO: this UUID of the annotation should be MD5-ed to obscure it
        # for security (like with hashlib.md5())
        self.json_annotation_fieldname_uuid = json_tstamp_fieldname_uuid


    @tornado.gen.coroutine
    def on_disconnect(self):
        self.log("on_disconnect")
        yield []
        self.log("on_disconnect done")
        return

    @tornado.gen.coroutine
    def handle_listening_at_client(self):
        try:
            self._read_line_from_client()
        except tornado.iostream.StreamClosedError:
            pass
        return


    @tornado.gen.coroutine
    def on_connect(self):
        self.log("on_connect")
        yield self.handle_listening_at_client()
        if self.forwarding_destination:
           # we need to forward first to another proxy, instead of answering
           # our client directly
           self.log("connecting to next forwarding proxy in the chain")
           forwarding_addr, forwarding_port = self.forwarding_destination.split(":")
           forwarding_port = int(forwarding_port)
           s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
           self.forw_stream = tornado.iostream.IOStream(s)
           self.forw_stream.connect((forwarding_addr, forwarding_port))

        return



    def log(self, msg, *args, **kwargs):
        print "[{}]: {}".format(self.client_addr, msg.format(*args, **kwargs))
        return


    @tornado.gen.coroutine
    def _read_line_from_client(self):
        self.client_stream.read_until('\n', self._handle_read_from_client)


    @tornado.gen.coroutine
    def _read_line_back_from_forwarder(self):
        self.forw_stream.read_until('\n', self._handle_read_back_from_forwarder)


    @tornado.gen.coroutine
    def _handle_read_from_client(self, data):
        self.log("received line from client {}", repr(data))
        data = data.rstrip('\r\n')        # remove the ending new-line
        # encode the JSON object with the annotation of the timestamp in this
        # proxy. Before adding the annotation in this proxy, we must try to
        # decode the read-data as a JSON object (if it was a JSON object read)
        try:
           object_read = tornado.escape.json_decode(str(data))
           # we expect that the JSON object decoded was a complex object
           # (like a Python Dictionary), not an elementary one (like an 'int')
           # If it was an elementary one, then we convert it to a dictionary
           if not isinstance(object_read, dict):
              object_read = {}
              object_read['line'] = str(data)
        except ValueError:
           # the data was raw-data, like a 'string', so it couldn't be JSON
           # decoded
           object_read = {}
           object_read['line'] = str(data)

        epoch_in_millis = str(int(time.time() * 1000))
        object_read[self.json_annotation_fieldname_uuid] = epoch_in_millis
        json_annotated_object = tornado.escape.json_encode(object_read)

        if self.forw_stream:
           self.log("forwarding line to next proxy {}", repr(data))
           yield self.forw_stream.write("%s\n" % json_annotated_object)
           self._read_line_back_from_forwarder()  # we just sent a line to fwd
        else:
           # we have no other forwarding proxy to send the data, so simply
           # answer directly to our client
           yield self.client_stream.write("%s\n" % json_annotated_object)
        self._read_line_from_client()



    @tornado.gen.coroutine
    def _handle_read_back_from_forwarder(self, data):
        self.log("received line back from forwader {}", repr(data))
        data = data.rstrip('\r\n')        # remove the ending new-line
        try:
           object_read = tornado.escape.json_decode(str(data))
           # we expect that the JSON object decoded was a complex object
           # (like a Python Dictionary), not an elementary one (like an 'int')
           # If it was an elementary one, then we convert it to a dictionary
           if not isinstance(object_read, dict):
              object_read = {}
              object_read['line'] = str(data)
        except ValueError:
           # the data was raw-data, like a 'string', so it couldn't be JSON
           # decoded
           object_read = {}
           object_read['line'] = str(data)

        # find our original annotation, that we put in the JSON object 
        # before sending it to the next forwarding proxy, back in the 
        # returned JSON object from the next forwarding proxy
        if self.json_annotation_fieldname_uuid in object_read: 
           original_time = object_read[self.json_annotation_fieldname_uuid]
           original_time = int(original_time)
           curr_epoch_in_millis = int(time.time() * 1000)
           delay_in_millis = str(curr_epoch_in_millis - original_time)
           # rewrite the timestamp of our original annotation with the delay
           object_read[self.json_annotation_fieldname_uuid] = delay_in_millis

        json_annotated_object = tornado.escape.json_encode(object_read)

        yield self.client_stream.write("%s\n" % json_annotated_object)
        self._read_line_from_client()




class ListeningServer(tornado.tcpserver.TCPServer):
    """ The listener server """

    def __init__(self, forwarding_dest):
        tornado.tcpserver.TCPServer.__init__(self)
        self._forwarding_destination = forwarding_dest


    def listen(self, port, address=""):
        tornado.tcpserver.TCPServer.listen(self, port, address="")
        if address:
           self._local_address = "%s:%d" % (address, port)
        else:
           self._local_address = "%s:%d" % (my_host_domain_name, port)


    @tornado.gen.coroutine
    def handle_stream(self, stream, clnt_address):

        client_address = "%s:%d" % (clnt_address[0], clnt_address[1])
        sys.stderr.write("DEBUG: Creating a new connection from %s\n" %
                          client_address)

        conn = EstablishedListener(stream, client_address, self._local_address,
                                   self._forwarding_destination)

        sys.stderr.write("DEBUG: yielding to conn.on_connect()\n")
        yield conn.on_connect()
        sys.stderr.write("DEBUG: exiting handle_stream\n")
        return




class ForwardingClient(object):
    """ This is an independent forwarding client, when there is no listener
        server, ie., when we listen (read) to standard-input and forward in TCP
    """

    def __init__(self, forwarding_destination):
        remote_addr, remote_port = forwarding_destination.split(":")
        self.forwarding_addr = remote_addr
        self.forwarding_port = int(remote_port)


    @tornado.gen.coroutine
    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.forw_stream = tornado.iostream.IOStream(s)
        self.forw_stream.connect((self.forwarding_addr, self.forwarding_port),
                            send_request)




def run_listener(listen_port, forwarding_dest=None,
                 debug_level=0):

    """
    Run TCP proxy on the specified [address:]port.

    req_callback: a callback that is passed a RequestObj that it should
        modify and then return
    resp_callback: a callback that is given a ResponseObj that it should
        modify and then return
    err_callback: in the case of an error, this callback will be called.
        there's no difference between how this and the resp_callback are
        used.
    debug_level: 0 no debug, 1 basic, 2 verbose
    """

    # http://tornado.readthedocs.org/en/latest/tcpserver.html
    if listen_port.find(":") != -1:
       # there is a local address to which to listen to
       local_addr, local_port = listen_port.split(":")
    else:
       local_addr = ""
       local_port = listen_port

    local_port = int(local_port)

    tcp_server = ListeningServer(forwarding_dest)
    tcp_server.listen(port=local_port, address=local_addr)

    ioloop = tornado.ioloop.IOLoop.instance()
    ioloop.start()



def on_read_from_stdin(fd, events):
    if events != tornado.ioloop.IOLoop.READ:
       ioloop = tornado.ioloop.IOLoop.instance()
       ioloop.remove_handler(0)
       ioloop.add_callback(lambda x: x.stop(), ioloop)
    else:
       buffer = sys.stdin.read(1024)
       if buffer:
          sys.stderr.write("READ %s" % buffer)
       else:
          # sys.stderr.write("EOF found on stdin\n")
          ioloop = tornado.ioloop.IOLoop.instance()
          ioloop.remove_handler(0)
          ioloop.add_callback(lambda x: x.stop(), ioloop)


def run_forwarder(forward_to_addr,
                  debug_level=0):

    ioloop = tornado.ioloop.IOLoop.instance()
    ioloop.add_handler(0, on_read_from_stdin, ioloop.READ|ioloop.ERROR)
    ioloop.start()


#### MAIN #####

def main():
    """Main() entry-point to this script."""

    timeout = 10
    stdinp_block_size = 512
    listen_port = None
    forward_to_addr = None
    remove_perf_headers = False

    global my_host_domain_name
    my_host_domain_name = socket.getfqdn()
    # Take all the DNS non letters or digits characters and
    # transform them into "_"
    my_field_host_dom_n = re.sub(r"[^a-zA-Z0-9]", "_", my_host_domain_name)

    # Get the usage string from the doc-string of this script
    # (ie. usage_string := doc_string )
    current_python_script_pathname = inspect.getfile(inspect.currentframe())
    dummy_pyscript_dirname, pyscript_filename = \
                os.path.split(os.path.abspath(current_python_script_pathname))
    pyscript_filename = os.path.splitext( pyscript_filename )[0] # no extension
    pyscript_metadata = __import__(pyscript_filename)
    pyscript_docstring = pyscript_metadata.__doc__

    # The ArgParser
    parser = argparse.ArgumentParser(description='Find the delays in each '
                                                 'subsegment of a connection.',
                                     epilog=pyscript_docstring,
                                     formatter_class=\
                                                  RawDescriptionHelpFormatter)
    parser.add_argument('-t', '--timeout', nargs=1, default=10, required=False,
                        type=int, metavar='timeout',
                        help='Specify the timeout for each operation. '
                             '(default: %(default)d seconds)')
    parser.add_argument('-l', '--listen', nargs=1, default=None, required=False,
                        metavar='listening-address',
                        help='Which TCP address:port to listen for incoming '
                             'packets. (default: %(default)s)')
    parser.add_argument('-f', '--forward_to', nargs=1, default=None,
                        required=False, metavar='proxy-addr',
                        help='To which TCP address:port to forward the '
                             'input data. (default: %(default)s)')
    parser.add_argument('-r', '--remove_perf_headers',
                        default=False, required=False,
                        action='store_true',
                        help='Whether to remove or not existing '
                             'performance headers in a packet '
                             '(default: %(default)s)')

    args = parser.parse_args()

    if args.forward_to:
       forward_to_addr = args.forward_to[0]
    if args.listen:
       listen_port = args.listen[0]
    if args.timeout:
       timeout = args.timeout
    if args.remove_perf_headers:
       remove_perf_headers = True

    if listen_port:
       print ("Starting TCP proxy on port %s" % listen_port)
       run_listener(listen_port, forward_to_addr)
    elif forward_to_addr:
       print ("Starting TCP forwarder to destination %s" % forward_to_addr)
       run_forwarder(forward_to_addr)



if __name__ == '__main__':
    main()





