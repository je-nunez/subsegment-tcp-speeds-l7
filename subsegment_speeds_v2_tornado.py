#!/usr/bin/env python
#
# Modified from:
#     https://pypi.python.org/pypi/quickproxy/0.2.0
# that is a Tornado HTTPproxy in the PyPi repo (but this script is a TCP proxy)
#

"""Program for helping to isolate which sub-segment in a network [or proxy host
in a network] influences more in the delay of a network transmission.

Formally, it works as chain of network proxies with send measure headers among
each proxy in the chain.

Invocation:

     subsegment-speeds.py  [-{l|-listen} <listen-addr>]
                           [-{f|-forward_to} <forward_to-address>]
                           [-{t|-timeout} <timeout>]
                           [-{r|-remove-perf-headers}]

     Command-line arguments:

          -{t|-timeout} <timeout>:       specify the timeout for each operation
                                         (default: 10 seconds)


          -{l|-listen} <listen-addr>:    which TCP address:port to listen for
                                         incoming packets. (default: none)

                                        If this option -{l|-listen} is not used,
                                        the program will read from the
                                        standard-input as fast as possible,
                                        inserting performance-headers every
                                        -{b|-block} bytes of read-data; the
                                        answered-data, in turn, will be printed
                                        to std-output.


          -{f|-forward_to} <forward_to-address>:       to which TCP address:port
                                                       to forward the input data
                                                       (default: none)

                                        The input data forwarded is the one read
                                        either by the -{l|-listen} address, or
                                        by standard-input if the -{l|-listen}
                                        address is omitted.

                                        If -{f|-forward_to} is omitted, then
                                        there will be no forwarding, and this
                                        command invocation will echo-back to the
                                        -{l|-listen} address whatever it
                                        receives from it.


          -{r|-remove-perf-headers}:     Whether to add or not the performance
                                         headers belonging to this hop in the
                                         packets (default: add them)


Example:

      This is an example with four hosts making up the chain of communication
      sub-segments in the network, the client A works with (connects to) B, B to
      C, and C to Z.

      B can be in another co-location or geographically remote in comparison to
      A, or be an entry point with heavy-load to another network, etc. The same
      applies with C in comparison to B, it can be in another co-location or
      geographically remote in comparison to C, etc; and so on in this
      delay-sensitive computer network.

           source host A:

                    subsegment-tcp-speeds.py  --forward_to  <host-B>:9000

                        In this case, A forwards its standard-input to the proxy
                        at B, and gets its answer (and time-delay stats) from B.

           intermediate host B:

                    subsegment-tcp-speeds.py  --listen  '*:9000'
                                              --forward_to  <host-C>:9000

                        In this case, B forwards its standard-input to the proxy
                        at C, and gets its answer (and time-delay stats) from C.

           intermediate host C:

                    subsegment-tcp-speeds.py  --listen  '*:9000'
                                              --forward_to  <host-Z>:9000

                        In this case, C forwards its standard-input to the proxy
                        at Z, and gets its answer (and time-delay stats) from Z.

           end host Z:

                    subsegment-tcp-speeds.py  --listen  '*:9000'

                        In this case, Z doesn't use a --forward_to option, so it
                        is the end backend which resolves client A's initial
                        request. This script simply echoes back the initial
                        request, so it sends back A's standard-input back to A
                        (and time-delay stats)."""


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

# import itertools
import tornado.ioloop
import tornado.iostream
import tornado.escape
import tornado.tcpclient
import tornado.tcpserver


class BaseAnnotatedConnection(object):
    """ This is the base class that represents an annotated connection,
    ie., an established TCP connection which has a field which represents
    the annotation this established connection adds, tracks, and analyzes
    inside the TCP connection

    Fields:
        _initial_annotation_key
                 the initial annotation key for when the packet first
                 enters this hop

        _final_annotation_key
                 the final annotation key (when the return, answer packet
                 exits this network hop


    Methods:
        self.__init__(string1, string2)
                     constructor. Builds the above two fields of the
                     annotation keys from the parameters string1 and
                     string2
    """

    def __init__(self, string1, string2):
        # first, clear the chactacters in both string[12]
        tmp_string1 = re.sub(r"[^a-zA-Z0-9]", "_", string1)
        tmp_string2 = re.sub(r"[^a-zA-Z0-9]", "_", string2)

        # build the initial annotation key (when the packet first enters
        # this network hop)
        my_salt = random.randint(0, 10000000)
        annotation_fieldname_uuid = "X_My_Annotation_%s_%s_%d" % \
              (tmp_string1, tmp_string2, my_salt)
        # TODO: this UUID of the annotation should be MD5-ed to obscure it
        # for security (like with hashlib.md5())
        self._initial_annotation_key = annotation_fieldname_uuid


        # build the final annotation key (when the return, answer packet
        # exits this network hop)
        annotation_fieldname_uuid = "Delay between %s and %s" % \
                                    (tmp_string1, tmp_string2)
        self._final_annotation_key = annotation_fieldname_uuid




class EstablishedListener(BaseAnnotatedConnection):
    """
        Per-connection object.
    """

    def __init__(self, stream, client_addr, local_addr, forwarding_dest):
        BaseAnnotatedConnection.__init__(self, client_addr, local_addr)

        self.client_stream = stream
        stream.set_close_callback(self.on_disconnect)
        stream.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        stream.socket.setsockopt(socket.IPPROTO_TCP, socket.SO_KEEPALIVE, 1)

        self.client_addr = client_addr  # the client which connect()-ed to us
        self.local_addr = local_addr    # our proxy listening address
        self.forwarding_destination = forwarding_dest # where to forward to
        self.forw_stream = None         # the stream connected to forward to


    @tornado.gen.coroutine
    def on_disconnect(self):
        """The remote client has desconnected from this listener."""
        self.log("on_disconnect")
        yield []
        self.log("on_disconnect done")
        return


    @tornado.gen.coroutine
    def handle_listening_at_client(self):
        """A remote client has connected from this listener
        so we need to read an input line from it."""
        try:
            self._read_line_from_client()
        except tornado.iostream.StreamClosedError:
            pass
        return


    @tornado.gen.coroutine
    def on_connect(self):
        """A remote client has connected to this listener,
        so we prepare to read a line from it and, at the same time,
        if there is a forwarding proxy to which we must send the
        input lines to, we open that forwarding socket/stream to it."""
        self.log("on_connect")
        yield self.handle_listening_at_client()
        if self.forwarding_destination:
           # we need to forward first to another proxy, instead of answering
           # our client directly
            self.log("connecting to next forwarding proxy in the chain")
            forward_addr, forward_port = self.forwarding_destination.split(":")
            forward_port = int(forward_port)
            forw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.forw_stream = tornado.iostream.IOStream(forw_socket)
            self.forw_stream.connect((forward_addr, forward_port))

        return



    def log(self, msg, *args, **kwargs):
        """Log."""
        print "[{}]: {}".format(self.client_addr, msg.format(*args, **kwargs))
        return


    @tornado.gen.coroutine
    def _read_line_from_client(self):
        """Read a line from the remote client, which doesn't have our
        annotations yet (it is the first time this line is seen by us)."""

        self.client_stream.read_until('\n', self._handle_read_from_client)


    @tornado.gen.coroutine
    def _read_line_back_from_forwarder(self):
        """Read a line which the forwarding proxy has answered back to us.
        So this line has already passed through us, so it was then annotated
        by us."""

        self.forw_stream.read_until('\n', self._handle_read_back_from_forwrdr)


    @tornado.gen.coroutine
    def _handle_read_from_client(self, data):
        """Handle a line read from the remote client, in order to add to it
        our annotations (this line is the first time is seen, so it doesn't
        have our annotations)."""

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
        object_read[self._initial_annotation_key] = epoch_in_millis
        json_annotated_object = tornado.escape.json_encode(object_read)

        if self.forw_stream:
            self.log("forwarding JSON to next proxy {}",
                     repr(json_annotated_object))
            yield self.forw_stream.write("%s\n" % json_annotated_object)
            self._read_line_back_from_forwarder()  # we just sent a line to fwd
        else:
           # we have no other forwarding proxy to send the data, so simply
           # answer directly to our client
            self.log("answering JSON back to client {}",
                     repr(json_annotated_object))
            yield self.client_stream.write("%s\n" % json_annotated_object)
        self._read_line_from_client()



    @tornado.gen.coroutine
    def _handle_read_back_from_forwrdr(self, data):
        """Handle a line answered back from the next hop we had forwarded to,
        in order to update our annotations we had put in this line before
        sending it to that forwarding proxy."""

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
        if self._initial_annotation_key in object_read:
            original_time = object_read[self._initial_annotation_key]
            original_time = int(original_time)
            curr_epoch_in_millis = int(time.time() * 1000)
            delay_in_millis = str(curr_epoch_in_millis - original_time)
            # the answering packet is doing its return trip, so delete the
            # old annotation key and annotate the packet with final key
            del object_read[self._initial_annotation_key]
            object_read[self._final_annotation_key] = delay_in_millis


        json_annotated_object = tornado.escape.json_encode(object_read)

        yield self.client_stream.write("%s\n" % json_annotated_object)
        self._read_line_from_client()




class ListeningServer(tornado.tcpserver.TCPServer):
    """ The listener server """

    def __init__(self, forwarding_dest):
        tornado.tcpserver.TCPServer.__init__(self)
        self._forwarding_destination = forwarding_dest
        self._local_address = ""  # yet unknown


    def listen(self, port, address=""):
        """ Listen at this address, and prepare what is our address
        to insert it as a JSON key when we annotate the incoming lines"""

        tornado.tcpserver.TCPServer.listen(self, port, address="")
        if address:
            self._local_address = "%s:%d" % (address, port)
        else:
            my_host_fqdn = socket.getfqdn()
            # Take all the DNS non letters or digits characters and
            # transform them into "_"
            my_host_fqdn = re.sub(r"[^a-zA-Z0-9]", "_", my_host_fqdn)

            self._local_address = "%s:%d" % (my_host_fqdn, port)


    @tornado.gen.coroutine
    def handle_stream(self, stream, clnt_address):
        """ We have received a new incoming connection from a remote client.
        Create a new established-connection object to handle it."""

        client_address = "%s:%d" % (clnt_address[0], clnt_address[1])
        sys.stderr.write("DEBUG: Creating a new connection from %s\n" %
                         client_address)

        conn = EstablishedListener(stream, client_address, self._local_address,
                                   self._forwarding_destination)

        sys.stderr.write("DEBUG: yielding to conn.on_connect()\n")
        yield conn.on_connect()
        sys.stderr.write("DEBUG: exiting handle_stream\n")
        return




class StdInputForwardingClient(BaseAnnotatedConnection):
    """ This is an independent forwarding client, when there is no listener
        server, ie., when we listen (read) to standard-input and forward in TCP
    """

    def __init__(self, forwarding_destination):
        BaseAnnotatedConnection.__init__(self, "stdin", forwarding_destination)

        remote_addr, remote_port = forwarding_destination.split(":")
        self.forwarding_addr = remote_addr
        self.forwarding_port = int(remote_port)
        self.forw_stream = None
        # convert sys.stdin to a Tornado IOStream
        self.stdin = tornado.iostream.PipeIOStream(sys.stdin.fileno())
        self.stdout = tornado.iostream.PipeIOStream(sys.stdout.fileno())


    @tornado.gen.coroutine
    def read_first_line_from_std_input(self):
        """Read the first line from the standard input."""
        self._read_line_from_std_input()


    @tornado.gen.coroutine
    def _read_line_from_std_input(self):
        """Read a line from the standard input, which doesn't have our
        annotations yet."""

        self.stdin.read_until('\n', self._handle_read_from_std_input)



    @tornado.gen.coroutine
    def _read_line_back_from_forwarder(self):
        """Read a line which the forwarding proxy has answered back to us.
        So this line has already passed through us, so it was then annotated
        by us."""

        self.forw_stream.read_until('\n', self._handle_read_back_from_forwrdr)


    @tornado.gen.coroutine
    def _handle_read_from_std_input(self, data):
        """ Standard-input has a line ready to be be read.
            Send this line to the next forwarder proxy, connecting before to it
            if necessary.
        """

        self.log("received line from standard-input {}", repr(data))

        data = data.rstrip('\r\n')        # remove the ending new-line
        # encode the JSON object with the annotation of the timestamp in this
        # proxy.
        dict_repr = {}
        dict_repr['line'] = str(data)

        epoch_in_millis = str(int(time.time() * 1000))
        dict_repr[self._initial_annotation_key] = epoch_in_millis
        json_annotated_object = tornado.escape.json_encode(dict_repr)

        if not self.forw_stream:
            self.log("connecting to fwd-ing proxy {}:{}",
                     self.forwarding_addr, self.forwarding_port
                    )
            self.connect()

        self.log("forwarding JSON to next proxy {}",
                 repr(json_annotated_object))
        yield self.forw_stream.write("%s\n" % json_annotated_object)
        yield self._read_line_back_from_forwarder()  # just sent a line to fwd
        # yield self._read_line_from_std_input()



    @tornado.gen.coroutine
    def connect(self):
        """ Connect to the remote forwarding server. """

        forw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.forw_stream = tornado.iostream.IOStream(forw_socket)
        self.forw_stream.connect((self.forwarding_addr, self.forwarding_port))


    @tornado.gen.coroutine
    def _handle_read_back_from_forwrdr(self, data):
        """Handle a line answered back from the next hop we had forwarded to,
        in order to update our annotations we had put in this line before
        sending it to that forwarding proxy.
        Then print results in our standard-output, since we had read initially
        from standard-input
        """

        self.log("received line back from forwarder {}", repr(data))
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
        if self._initial_annotation_key in object_read:
            original_time = object_read[self._initial_annotation_key]
            original_time = int(original_time)
            curr_epoch_in_millis = int(time.time() * 1000)
            delay_in_millis = str(curr_epoch_in_millis - original_time)
            # the answering packet is doing its return trip, so delete the
            # old annotation key and annotate the packet with final key
            del object_read[self._initial_annotation_key]
            object_read[self._final_annotation_key] = delay_in_millis

        # dump the annotations received from the network loop to std-out
        for key in object_read:
            if key != 'line':
                yield self.stdout.write("%s = %s\n" % \
                                  (str(key), str(object_read[key])))

        # Write the original line back to the std-out (an echo of origina;
        # line)
        if 'line' in object_read:
            yield self.stdout.write("Line %s\n" % str(object_read['line']))

        yield self._read_line_from_std_input()
        # yield self._read_line_back_from_forwarder()



    def log(self, msg, *args, **kwargs):
        """Log."""
        print "[{}:{}]: {}".format(self.forwarding_addr, self.forwarding_port,
                                   msg.format(*args, **kwargs))
        return




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



def run_forwarder(forward_to_addr,
                  debug_level=0):
    """ Run the forwarder from standard-input to a remote proxy. """

    stdin_readr = StdInputForwardingClient(forward_to_addr)
    ioloop = tornado.ioloop.IOLoop.instance()
    stdin_readr.read_first_line_from_std_input()
    ioloop.start()



#### MAIN #####

def main():
    """Main() entry-point to this script."""

    timeout = 10
    listen_port = None
    forward_to_addr = None
    remove_perf_headers = False

    # Get the usage string from the doc-string of this script
    # (ie. usage_string := doc_string )
    current_python_script_pathname = inspect.getfile(inspect.currentframe())
    dummy_pyscript_dirname, pyscript_filename = \
                os.path.split(os.path.abspath(current_python_script_pathname))
    pyscript_filename = os.path.splitext(pyscript_filename)[0] # no extension
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
                        help='Whether to add or not the performance headers '
                             'belonging to this hop in the packets '
                             '(default: add them)')

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
        print "Starting TCP proxy on port %s" % listen_port
        run_listener(listen_port, forward_to_addr)
    elif forward_to_addr:
        print "Starting TCP forwarder to destination %s" % forward_to_addr
        run_forwarder(forward_to_addr)



if __name__ == '__main__':
    main()





