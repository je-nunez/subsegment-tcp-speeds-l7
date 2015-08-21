#!/usr/bin/env python
#
# Modified from:
#     https://pypi.python.org/pypi/quickproxy/0.2.0
# that is a Tornado HTTPproxy in the PyPi repo (but this script is a TCP proxy)
#
# pylint: disable=too-many-arguments

"""Program for helping to isolate which sub-segment in a network [or proxy host
in a network] influences more in the delay of a network transmission.

Formally, it works as chain of network proxies with send measure headers among
each proxy in the chain.

Invocation:

     subsegment-speeds.py  [-{l|-listen} <listen-addr>]
                           [-{f|-forward_to} <forward_to-address>]
                           [-{d|-debug} <debug-level>]
                           [-{r|-remove-perf-headers}]

     Command-line arguments:

          -{d|-debug} <debug-level>:     debug level (0: emerg ... 7: debug)


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


          -{n|-dont-add-perf-headers}:     Whether to add or not the performance
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


# The difference of this script is that it works in ISO/OSI layer 7: traceroute,
# tcptraceroute, pathchar, pchar, and similar programs, work at the IP layer 3
# or at the TCP layer 4, so this script is more similar to a layered structure
# of proxies like Varnish, HAProxy, Nginx, PHP-FPM (or F5 BigIP iRules if you
# want) interconnected with one another, so what this script does is that each
# layer inserts its own OSI layer-7 annotations into the packets it proxies, and
# then process them back when the return packet is answered. This is similar in
# idea with HAProxy's or Squid's HTTP header insertion, although this proxy
# works with TCP, not strictly HTTP.
#
#    haproxy.cfg:
#            ...
#        http-request add-header "X-my-http-header-timeStamp-at-Proxy"  "%ms"
#        # (or better:
#        http-request add-header "X-my-http-header-timeStamp-at-Proxy"  "%f %ms"
#
#  Or Squid in a reverse-proxy config with:
#
#    squid.conf:
#            ...
#        request_header_add  X-my-http-header-timeStamp-at-Proxy  "%tS"
#


import sys
import os
import argparse
from argparse import RawDescriptionHelpFormatter
import inspect
from datetime import datetime
# import time
import socket
import re
import random

# import itertools
import tornado.ioloop
import tornado.iostream
import tornado.escape
import tornado.tcpclient
import tornado.tcpserver

# The origin of the Unix time (the origin of the Epoch)

EPOCH_ORIGIN = None

# On debugging (option -d <debug_level>)
#
# Not all platforms have the Python "enum" module installed
# ( https://pypi.python.org/pypi/enum34 ), so we don't use an enumerative class
# to represent the debug values. For them, we use the default Unix's syslog
# values to debug:
#    Debug     =  7
#    Info      =  6
#    Notice    =  5
#    Warning   =  4
#    Error     =  3
#    Critical  =  2
#    Alert     =  1
#    Emergency =  0


#
# class BaseAnnotatedConnection(object):
#

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

        _log_verbosity
                 the level of verbosity in the logs above which the messages
                 will be silently ignored

        _log_tag_preffix
                 the tag with which to prefix the log messages printed

    Methods:
        self.__init__(string1, string2, log_verbosity, log_tag_preffix):
                     constructor. Builds the above two fields of the
                     annotation keys from the parameters string1 and
                     string2.
                     The log_verbosity and log_tag parameters go to
                     the corresponding fields.

       self.log(severity, msg, *args, **kwargs):
                     Writes a message if the severity of the msg is the
                     same or lower than self._log_verbosity
    """

    def __init__(self, string1, string2, log_verbosity, log_tag_preffix):
        # first, clear the chactacters in both string[12]
        self._initiator_str = re.sub(r"[^a-zA-Z0-9]", "_", string1)
        self._next_hop_str = re.sub(r"[^a-zA-Z0-9]", "_", string2)
        self._general_log_tag = log_tag_preffix

        # The debug log level and msg-preffix to use for this instance
        self._log_verbosity = log_verbosity

        # build the final annotation key (when the return, answer packet
        # exits this network hop). This final annotation doesn't have
        # a cookie (salt)
        annotation_fieldname_uuid = "Delay between %s and %s" % \
                                    (self._initiator_str, self._next_hop_str)
        self._final_annotation_key = annotation_fieldname_uuid

        # build the very initial annotation cookie (salt) (before the packet
        # first enters this network hop)
        self.set_cookie(str(random.randint(0, 10000000)))

    def peek_possible_annotation_key(self, cookie):
        """Peek the possible annotation key for a cookie."""
        return "X_My_Annotation_%s_%s_%s" % \
                    (self._initiator_str, self._next_hop_str, cookie)

    def set_cookie(self, cookie):
        """Some values we annotate into the packets or log, append a cookie
        for easier identification and tracking across the chain of proxies."""

        # set the self._initial_annotation_key according to the given cookie
        self._initial_annotation_key = "X_My_Annotation_%s_%s_%s" % \
              (self._initiator_str, self._next_hop_str, cookie)

        self._log_tag_preffix = '%s -%s' % (self._general_log_tag, cookie)

    def log(self, msg_severity, msg, *args, **kwargs):
        """Print the log message if its severity is important enough."""

        if msg_severity <= self._log_verbosity:
            sys.stderr.write("[{}]: {}\n".format(self._log_tag_preffix,
                                                 msg.format(*args, **kwargs)))


#
# class EstablishedListener(BaseAnnotatedConnection):
#

class EstablishedListener(BaseAnnotatedConnection):
    """
        Object to represent an incoming connection to us (and the corresponding
        forwarding connection to the next proxy if it applies)
    """

    def __init__(self, stream, client_addr, local_addr, forwarding_dest,
                 dont_add_perf_headers, log_verbosity):
        """Instance constructor.
           Arguments:

              stream: it has the incoming connection to us
              client_addr: the client address that connected to us
              local_addr: our local address that accepted the incoming conn.
              forwarding_dest: the next proxy addr to which to forward (if any)
              dont_add_perf_headers: don't annotate packets in this instance
              log_verbosity: the minimum severity of log-messages to report
        """
        # Call the inherited constructor in our base class
        BaseAnnotatedConnection.__init__(self, local_addr, client_addr,
                                         log_verbosity, client_addr)

        self.client_stream = stream
        stream.set_close_callback(self.on_incoming_client_disconnect)
        stream.set_nodelay(True)            # TCP_NODELAY option
        stream.socket.setsockopt(socket.IPPROTO_TCP, socket.SO_KEEPALIVE, 1)

        self.client_addr = client_addr  # the client which connect()-ed to us
        self.forwarding_destination = forwarding_dest  # where to forward to
        self.forw_stream = None         # we still don't have a fwd connection
        self._dont_add_perf_headers = dont_add_perf_headers
        self._cookie_cloned = False     # our cookie (or salt) is still random

    @tornado.gen.coroutine
    def prepare_incoming_connection(self):
        """This is the first method called in an object of this class after it
        was created. It doesn't belong to the object constructor above because
        it is a co-routine, so it allows that an incoming line from the client
        be read while this co-routine tries to set-up the forwarding connection
        to the next proxy down the loop (if any).

        So the story at this point is that a remote client has just connected
        to this object, so we prepare to read a line from it and, concurrently,
        we don't lose time and, if there is a forwarding proxy to which we
        must send the input lines to, we open now that forwarding
        socket/stream to it."""

        self.log(7, "prepare_incoming_connection")

        # handle this incoming connection
        yield self.handle_new_incoming_connection()

        if self.forwarding_destination and not self.forw_stream:
            # we need to forward first to another proxy, instead of answering
            # our client directly
            self.log(6, "connecting to next forwarding proxy in the chain {}",
                     self.forwarding_destination)
            forward_addr, forward_port = self.forwarding_destination.split(":")
            forward_port = int(forward_port)
            forw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.forw_stream = tornado.iostream.IOStream(forw_socket)
            self.forw_stream.connect((forward_addr, forward_port))
            self.forw_stream.set_close_callback(self.on_forwarder_disconnect)
            self.forw_stream.set_nodelay(True)  # TCP_NODELAY option
            self.forw_stream.socket.setsockopt(socket.IPPROTO_TCP,
                                               socket.SO_KEEPALIVE, 1)

        return

    @tornado.gen.coroutine
    def handle_new_incoming_connection(self):
        """A remote client has connected from this listener
        so we need to read an input line from it."""
        try:
            self._read_line_from_client()
        except tornado.iostream.StreamClosedError:
            pass  # see callback on_incoming_client_disconnect() below
        return

    @tornado.gen.coroutine
    def on_incoming_client_disconnect(self):
        """The incoming client has desconnected from this listener."""
        self.log(7, "on_disconnect incoming client")
        yield []

        if self.forw_stream and not self.forw_stream.closed():
            # if we also have a connection to an upstream, forwarding proxy
            # that is still open, then close it as well
            self.forw_stream.close()

        self.log(5, "incoming client has disconnected")
        return

    @tornado.gen.coroutine
    def on_forwarder_disconnect(self):
        """The forwarder has disconnected from us."""
        self.log(7, "on_forwarder_disconnect")

        # TODO: should it retry to re-open a new connection to upstream?
        # ie, to the forwarding proxy? If so, how many times to attempt
        # reconnecting?

        yield []

        if self.client_stream and not self.client_stream.closed():
            # if we also have the incoming downstream client connection that is
            # still open, then close it as well
            self.client_stream.close()

        self.log(3, "forwarding-proxy has disconnected from us")
        return

    @tornado.gen.coroutine
    def _read_line_from_client(self):
        """Read a line from the incoming client, which doesn't have our
        annotations yet (it is the first time this line is seen by us)."""

        self.client_stream.read_until('\n', self._handle_read_from_client)

    @tornado.gen.coroutine
    def _read_line_back_from_forwarder(self):
        """Read a line which the forwarding proxy has answered back to us.
        So this line has already passed through us, so it was then annotated
        by us."""

        self.forw_stream.read_until('\n', self._handle_read_back_from_forwrdr)

    def _clone_transaction_cookie(self, incomming_dict_from_client):
        """Try to set our cookie (or 'salt') to be the same cookie (or
        'salt') as was received from the incoming client connection, instead
        of using a random cookie (or 'salt')

        In this way, while it is true that each proxy in the connection chain
        does insert its own annotations into the packet independently of the
        other proxies in the chain:

            X_My_Annotation_<client_1>_<cookie1>: <value-from-client-1>
            X_My_Annotation_<client_2>_<cookie2>: <value-from-client-2>
            ...
            X_My_Annotation_<client_N>_<cookieN>: <value-from-client-N>

        it is true too that each proxy will try to use the same <cookie> (or
        'salt') as it has received from its client proxy (ie, all of
        '_<cookie[i]>' suffixes in the keys above should be the same)."""

        # Try to find the first key in the "incomming_dict_from_client" which
        # starts with the prefix "X_My_Annotation_": then, for such
        # pre-existing key, its suffix "_<cookie>" is the <cookie> (salt) we
        # received from the client and we must re-use as our same <cookie>
        a_key = ''
        for key in incomming_dict_from_client:      # search incoming keys
            if key.startswith('X_My_Annotation_'):  # search is sucessful
                a_key = key
                break

        if not a_key:
            # We couldn't find an incoming key with such prefix. As an
            # optimization, we say that the cookie was set, because we
            # shouldn't be calling this procedure -which does the above
            # search- for each received packet (dictionary), only for the
            # very first, and then, for this first packet (dict) received,
            # inherit its incoming cookie (or not, as is in this case, where
            # we continue using our random cookie)
            self.log(4, "incoming client didn't add its annotation into the "
                        "first packet for us to clone its ID-cookie in it")
            self._cookie_cloned = True     # don't try to call this search again
            return

        # The value of the incoming key is 'X_My_Annotation_..._<cookie>', so
        # we try to split it by '_' and get the last value, that is the cookie
        client_cookie = a_key.rpartition('_')[-1]
        my_possible_key = self.peek_possible_annotation_key(client_cookie)
        # Check if 'my_possible_key' for annotating is not already in use by
        # another client for its own annotation, so I don't overwrite its
        # annotations
        if my_possible_key not in incomming_dict_from_client:
            # ok: no other client has used my possible key for its annotations
            old_log_tag_preffix = self._log_tag_preffix
            self.set_cookie(client_cookie)   # clone incoming client cookie
            self.log(7, "no longer using log-tag: '%s': hop has cloned the "
                        "same ID-cookie for its annotations as the same "
                        "ID-cookie its client is using for its respective "
                        "annotations" % old_log_tag_preffix)
        self._cookie_cloned = True     # don't try to call this search again

    @tornado.gen.coroutine
    def _handle_read_from_client(self, in_line_from_client):
        """Handle a line read from the incoming client, in order to add to it
        our perf annotations (this line is the first time is seen, so it doesn't
        have our annotations).
        Then, in the second half of this function, answer the new packet back
        to the incoming client, xor, if we have to forward instead this packet
        to a next proxy, do so, expecting an answer from back from it in the
        future.
        """

        self.log(7, "received line from client {}", repr(in_line_from_client))
        in_line_from_client = in_line_from_client.rstrip('\r\n')
        # encode the JSON object with the annotation of the timestamp in this
        # proxy. Before adding the annotation in this proxy, we must try to
        # decode the read-data as a JSON object (if it was a JSON object read)
        try:
            object_read = tornado.escape.json_decode(str(in_line_from_client))
            # we expect that the JSON object decoded was a complex object
            # (like a Python Dictionary), not an elementary one (like an 'int')
            # If it was an elementary one, then we convert it to a dictionary
            if not isinstance(object_read, dict):
                self.log(5, "The incoming client didn't send us a dictionary:"
                         " we'll wrap its line {}", repr(in_line_from_client))
                object_read = {}
                object_read['line'] = str(in_line_from_client)
        except ValueError:
            # the input line from the client was raw-data, like a 'string', so
            # it couldn't be JSON decoded
            self.log(4, "The incoming client didn't send us a JSON object:"
                     " is it trying a direct connection. Its line was: {}",
                     repr(in_line_from_client))
            object_read = {}
            object_read['line'] = str(in_line_from_client)

        # At this point we have decoded in layer 7 the dictionary "object_read"
        # that the remote, incoming client has sent us.

        if not self._dont_add_perf_headers:
            # we add our annotations in this packet. We only happen to annotate
            # our current epoch-time in milliseoconds, although we could add
            # more annotations
            if not self._cookie_cloned:
                # Our cookie has still its random initial value, so try to
                # clone the same cookie received from the client
                self._clone_transaction_cookie(object_read)
            now = datetime.now()
            global EPOCH_ORIGIN
            delta_epoch = (now - EPOCH_ORIGIN)
            value = delta_epoch.seconds + delta_epoch.microseconds / 1000000
            object_read[self._initial_annotation_key] = str(value)
            self.log(7, "Annoting with time %d" % value)

        json_annotated_object = tornado.escape.json_encode(object_read)

        if self.forw_stream:
            # we have a forwarding proxy down the loop to which to send the data
            self.log(6, "forwarding JSON to next proxy down the loop {}",
                     repr(json_annotated_object))
            yield self.forw_stream.write("%s\n" % json_annotated_object)
            self._read_line_back_from_forwarder()  # we just sent a line to fwd
        else:
            # we have no other forwarding proxy to send the data, so simply
            # answer directly to our client
            self.log(6, "answering JSON back to incoming client {}",
                     repr(json_annotated_object))
            yield self.client_stream.write("%s\n" % json_annotated_object)
        self._read_line_from_client()

    @tornado.gen.coroutine
    def _handle_read_back_from_forwrdr(self, line_answered_back_from_forwdr):
        """Handle a line answered back from the next hop we had forwarded to,
        ie., this is not an incoming line that 'self.client_stream' send us,
        but a returning line that 'self.forw_stream' is answering back to us.

        We have to update our annotations we had put in this line before
        sending it to that forwarding proxy 'self.forw_stream'. For this reason,
        one difference between
                 self._handle_read_from_client()
        and this
                 self._handle_read_back_from_forwrdr()
        is that the latter is more strict in its error checking -because we
        know what we had annotated into the packet before sending it to the
        forwarder-, while the former method is more lax because we don't know
        what annotations the remote, incoming client had done.
        """

        self.log(6, "received a line back from forwader {}",
                 repr(line_answered_back_from_forwdr))
        line_answered_back_from_forwdr = \
                             line_answered_back_from_forwdr.rstrip('\r\n')
        try:
            object_answered = tornado.escape.json_decode(
                str(line_answered_back_from_forwdr))

            # we expect that the JSON object decoded was a complex object
            # (like a Python Dictionary), not an elementary one (like an 'int')
            # If it was an elementary one, then we convert it to a dictionary
            if not isinstance(object_answered, dict):
                self.log(3, "The forwarding proxy didn't answer a dictionary:"
                         " we'll wrap its line {}",
                         repr(line_answered_back_from_forwdr))
                object_answered = {}
                object_answered['line'] = str(line_answered_back_from_forwdr)
        except ValueError:
            # the data was raw-data, like a 'string', so it couldn't be JSON
            # decoded
            self.log(3, "The forwarding proxy didn't answer a JSON object:"
                     " Its line was: {}",
                     repr(line_answered_back_from_forwdr))
            object_answered = {}
            object_answered['line'] = str(line_answered_back_from_forwdr)

        # find our original annotation, that we put in the JSON object
        # before sending it to the next forwarding proxy, back in the
        # returned JSON object from the next forwarding proxy
        if not self._dont_add_perf_headers:
            # we had added our annotation inside this line, so we expect
            # to find our annotation key in this dictionary
            if self._initial_annotation_key not in object_answered:
                self.log(3, "We didn't find our annotation key '{}' back"
                         " in the line answered back from forwarder: {}",
                         self._initial_annotation_key,
                         repr(line_answered_back_from_forwdr))
            else:
                # our annotation key is inside the object_answered from forwrdr
                original_time = object_answered[self._initial_annotation_key]
                try:
                    # Our annotation was an "float", so try to decode it back
                    original_time = float(original_time)
                    now = datetime.now()
                    global EPOCH_ORIGIN
                    delta_epoch = (now - EPOCH_ORIGIN)
                    curr_epoch = delta_epoch.seconds + delta_epoch.microseconds / 1000000
                    delay_micros = str(curr_epoch - original_time)
                    # annotate the packet with our final key
                    object_answered[self._final_annotation_key] = delay_micros
                except ValueError:
                    self.log(3, "We didn't find our float-pt annotation, but a"
                             " generic string annotation '{}' as value for our"
                             " annotation key '{}' in the line answered back"
                             " from forwarder: {}",
                             object_answered[self._initial_annotation_key],
                             self._initial_annotation_key,
                             repr(line_answered_back_from_forwdr))
                finally:
                    # the answering packet is doing its return trip, so delete
                    # the old annotation key
                    del object_answered[self._initial_annotation_key]

        json_annotated_object = tornado.escape.json_encode(object_answered)

        # relay the answer from our upstream to our original incoming client
        yield self.client_stream.write("%s\n" % json_annotated_object)
        self._read_line_from_client()


#
# class ListeningServer(tornado.tcpserver.TCPServer):

class ListeningServer(tornado.tcpserver.TCPServer):
    """ The listener server, which opens the listening socket and, once
        it accepts an incoming connections, creates the
        EstablishedListener instance to handle this incoming connection. """

    def __init__(self, forwarding_dest, dont_add_perf_headers,
                 log_verbosity):
        tornado.tcpserver.TCPServer.__init__(self)
        self._forwarding_destination = forwarding_dest
        self._dont_add_perf_headers = dont_add_perf_headers
        self._local_address = ""  # we don't know yet where we should listen
        self._log_verbosity = log_verbosity

    def listen(self, port, address=""):
        """ Listen at this local address, and prepare what is our address
        to insert it as a JSON key when we annotate the incoming lines"""

        if self._log_verbosity >= 5:
            print "Starting TCP proxy on port %s" % port

        tornado.tcpserver.TCPServer.listen(self, port, address)
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
        if self._log_verbosity >= 5:
            sys.stderr.write("NOTICE: Accepting incoming connection from %s\n" %
                             client_address)

        conn = EstablishedListener(stream, client_address, self._local_address,
                                   self._forwarding_destination,
                                   self._dont_add_perf_headers,
                                   self._log_verbosity)

        if self._log_verbosity == 7:
            sys.stderr.write("DEBUG: yielding to c.prepare_incoming_connection")
        yield conn.prepare_incoming_connection()
        if self._log_verbosity == 7:
            sys.stderr.write("DEBUG: exiting handle_stream\n")

        return


#
# class StdInputForwardingClient(BaseAnnotatedConnection):
#

class StdInputForwardingClient(BaseAnnotatedConnection):
    """ This is an independent forwarding client, when there is no listener
        server, ie., when we listen to (read from) standard-input and forward
        what we read from std-input to a next proxy.
        Ie., instances of this class is the very origin of the loop and ending
        point of it.
    """

    def __init__(self, forwarding_destination, dont_add_perf_headers,
                 log_verbosity):
        BaseAnnotatedConnection.__init__(self, "stdin", forwarding_destination,
                                         log_verbosity, forwarding_destination)

        remote_addr, remote_port = forwarding_destination.split(":")
        self.forwarding_addr = remote_addr      # we need to forward to the next
        self.forwarding_port = int(remote_port)  # proxy to this address:port
        self.forw_stream = None   # we are not connected yet to this fwd proxy
        self._dont_add_perf_headers = dont_add_perf_headers
        # convert sys.stdin to a Tornado IOStream, to read from it asynchron,
        self.stdin = tornado.iostream.PipeIOStream(sys.stdin.fileno())
        self.stdout = tornado.iostream.PipeIOStream(sys.stdout.fileno())

        self.stdin.set_close_callback(self.on_stdinput_eof)

    @tornado.gen.coroutine
    def on_stdinput_eof(self):
        """EOF on our standard-input."""
        self.log(7, "on_stdinput_eof")

        # Prepare to stop the Tornado IOLoop, since there is the EOF of
        # standard-input, ie., there is no more lines (from stdin) to forward

        ioloop = tornado.ioloop.IOLoop.instance()
        ioloop.remove_handler(0)
        ioloop.add_callback(lambda x: x.stop(), ioloop)

        yield []
        self.log(3, "EOF-standard-input")
        return

    @tornado.gen.coroutine
    def read_first_line_from_std_input(self):
        """Read the very first line from the standard input."""
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
    def _handle_read_from_std_input(self, input_line):
        """ Standard-input has a line ready to be processed.
            Send this line to the next forwarder proxy, connecting before to it
            if necessary.
        """

        self.log(7, "received line from standard-input {}", repr(input_line))

        input_line = input_line.rstrip('\r\n')    # remove the ending new-line
        # encode the JSON object with the annotation of the timestamp in this
        # proxy.
        dict_repr = {}
        dict_repr['line'] = str(input_line)

        # annotate this line (dictionary) adding our headers
        if not self._dont_add_perf_headers:
            now = datetime.now()
            delta_epoch = (now - EPOCH_ORIGIN)
            value = delta_epoch.seconds + delta_epoch.microseconds / 1000000
            dict_repr[self._initial_annotation_key] = str(value)

        # convert our dictionary to a JSON object before transmission
        json_annotated_object = tornado.escape.json_encode(dict_repr)

        if not self.forw_stream:
            # we hadn't connected yet to the next proxy in our loop
            self.log(5, "connecting to forwarding proxy {}:{}",
                     self.forwarding_addr, self.forwarding_port
                    )
            self.connect()

        self.log(6, "forwarding JSON to next proxy {}",
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
        self.forw_stream.set_close_callback(self.on_forwarder_disconnect)
        self.forw_stream.set_nodelay(True)                # TCP_NODELAY option
        self.forw_stream.socket.setsockopt(socket.IPPROTO_TCP,
                                           socket.SO_KEEPALIVE, 1)

    @tornado.gen.coroutine
    def on_forwarder_disconnect(self):
        """The forwarder has disconnected from us."""

        self.log(7, "on_forwarder_disconnect")

        # Prepare to stop the Tornado IOLoop, since the forwarding-proxy has
        # disconnected from us
        # TODO: should it retry to re-open a new connection to upstream?
        # ie, to the forwarding proxy? If so, how many times to attempt
        # reconnecting?
        ioloop = tornado.ioloop.IOLoop.instance()
        ioloop.remove_handler(0)
        ioloop.add_callback(lambda x: x.stop(), ioloop)

        yield []
        self.log(3, "forwarding-proxy has disconnected from us")
        return

    @tornado.gen.coroutine
    def _handle_read_back_from_forwrdr(self, line_answered_back_from_forwdr):
        """Handle a line answered back from the next hop we had forwarded to,
        in order to update our annotations we had put in this line before
        sending it to that forwarding proxy.
        Then print results in our standard-output, since we had read initially
        from standard-input
        """

        self.log(6, "received line back from forwarder {}",
                 repr(line_answered_back_from_forwdr))
        line_answered_back_from_forwdr = \
                             line_answered_back_from_forwdr.rstrip('\r\n')
        try:
            object_answered = tornado.escape.json_decode(
                str(line_answered_back_from_forwdr))
            # we expect that the JSON object decoded was a complex object
            # (like a Python Dictionary), not an elementary one (like an 'int')
            # If it was an elementary one, then we convert it to a dictionary
            if not isinstance(object_answered, dict):
                self.log(3, "The forwarding proxy didn't answer a dictionary:"
                         " we'll wrap its line {}",
                         repr(line_answered_back_from_forwdr))
                object_answered = {}
                object_answered['line'] = str(line_answered_back_from_forwdr)
        except ValueError:
            # the data was raw-data, like a 'string', so it couldn't be JSON
            # decoded
            self.log(3, "The forwarding proxy didn't answer a JSON object:"
                     " Its line was: {}",
                     repr(line_answered_back_from_forwdr))
            object_answered = {}
            object_answered['line'] = str(line_answered_back_from_forwdr)

        # find our original annotation, that we put in the JSON object
        # before sending it to the next forwarding proxy, back in the
        # returned JSON object from the next forwarding proxy
        if not self._dont_add_perf_headers:
            # we had added our annotation inside this line, so we expect
            # to find our annotation key in this dictionary
            if self._initial_annotation_key not in object_answered:
                self.log(3, "We didn't find our annotation key '{}' back"
                         " in the line answered back from forwarder: {}",
                         self._initial_annotation_key,
                         repr(line_answered_back_from_forwdr))
            else:
                # our annotation key is inside the object_answered from forwrdr
                original_time = object_answered[self._initial_annotation_key]
                try:
                    # Our annotation was an "float", so try to decode it back
                    original_time = float(original_time)
                    now = datetime.now()
                    global EPOCH_ORIGIN
                    delta_epoch = (now - EPOCH_ORIGIN)
                    curr_epoch = delta_epoch.seconds + delta_epoch.microseconds / 1000000
                    delay_micros = str(curr_epoch - original_time)
                    # annotate the packet with our final key
                    object_answered[self._final_annotation_key] = delay_micros
                except ValueError:
                    self.log(3, "We didn't find our float-pt annotation, but a"
                             " generic string annotation '{}' as value for our"
                             " annotation key '{}' in the line answered back"
                             " from forwarder: {}",
                             object_answered[self._initial_annotation_key],
                             self._initial_annotation_key,
                             repr(line_answered_back_from_forwdr))
                finally:
                    # the answering packet is doing its return trip, so delete
                    # the old annotation key
                    del object_answered[self._initial_annotation_key]

        # dump the annotations received from the network loop to std-out
        # Note that this dump is not affected by the value of our
        # self._dont_add_perf_headers, because this forwarding-loop
        # perhaps didn't add the performance annotations for this loop,
        # but other loops indirectly connected to this could have added
        # their respective annotations on performance headers, so we
        # need to print them
        for key in sorted(object_answered):
            if key != 'line':
                yield self.stdout.write("<-- %s = %s\n" % \
                                  (str(key), str(object_answered[key])))

        # Write the original line back to the std-out (an echo of origina;
        # line)
        if 'line' in object_answered:
            yield self.stdout.write("< Line: %s\n" % \
                                             str(object_answered['line']))

        yield self._read_line_from_std_input()
        # yield self._read_line_back_from_forwarder()


#
# function run_listener(...):
#
#   a utility wrapper creating an object of the class
#   ListeningServer(tornado.tcpserver.TCPServer) and
#   start the Tornado IOLoop
#

def run_listener(listen_addr, forwarding_dest=None,
                 dont_add_perf_headers=False, debug_level=0):

    """ Run TCP proxy 'ListeningServer' on the specified 'listen_addr', to
        optionally forward to a next upstream proxy at address
        'forwarding_dest'.

        Start the Tornado IOLoop
    """

    # http://tornado.readthedocs.org/en/latest/tcpserver.html
    if listen_addr.find(":") != -1:
        # there is a local address to which to listen to
        local_addr, local_port = listen_addr.split(":")
    else:
        local_addr = ""
        local_port = listen_addr

    local_port = int(local_port)

    tcp_server = ListeningServer(forwarding_dest, dont_add_perf_headers,
                                 debug_level)
    tcp_server.listen(port=local_port, address=local_addr)

    ioloop = tornado.ioloop.IOLoop.instance()
    ioloop.start()


#
# function run_forwarder(...):
#
#   a utility wrapper creating an object of the class
#   StdInputForwardingClient(...) and start the Tornado IOLoop
#

def run_forwarder(forward_to_addr, dont_add_perf_headers=False,
                  debug_level=0):
    """ Run the forwarder from standard-input to a remote proxy, ie.,
        an object of the class StdInputForwardingClient()

        Start the Tornado IOLoop.
    """

    stdin_readr = StdInputForwardingClient(forward_to_addr,
                                           dont_add_perf_headers, debug_level)
    ioloop = tornado.ioloop.IOLoop.instance()
    stdin_readr.read_first_line_from_std_input()
    ioloop.start()


#  *** MAIN FUNCTION ***
def main():
    """Main() entry-point to this script."""

    debug_level = 5     # 0: emerg; ... 6: informational; 7: debug
    listen_port = None
    forward_to_addr = None
    dont_add_perf_headers = False

    # Get the usage string from the doc-string of this script
    # (ie. usage_string := doc_string )
    current_python_script_pathname = inspect.getfile(inspect.currentframe())
    dummy_pyscript_dirname, pyscript_filename = \
                os.path.split(os.path.abspath(current_python_script_pathname))
    pyscript_filename = os.path.splitext(pyscript_filename)[0]  # no extension
    pyscript_metadata = __import__(pyscript_filename)
    pyscript_docstring = pyscript_metadata.__doc__

    # The ArgParser
    parser = argparse.ArgumentParser(description='Find the delays in each '
                                                 'subsegment of a connection.',
                                     epilog=pyscript_docstring,
                                     formatter_class=\
                                                  RawDescriptionHelpFormatter)
    parser.add_argument('-d', '--debug', nargs=1, default=5, required=False,
                        type=int, metavar='debug',
                        help='Specify the debug-level for which to report. '
                             '(default: %(default)d)')
    parser.add_argument('-l', '--listen', nargs=1, default=None, required=False,
                        metavar='listening-address',
                        help='Which TCP address:port to listen for incoming '
                             'packets. (default: %(default)s)')
    parser.add_argument('-f', '--forward_to', nargs=1, default=None,
                        required=False, metavar='proxy-addr',
                        help='To which TCP address:port to forward the '
                             'input data. (default: %(default)s)')
    parser.add_argument('-n', '--dont-add-perf-headers',
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
    if args.debug:
        if isinstance(args.debug, list):
            # this type check is necessary for some argparse.ArgumentParser()
            # installed in Mac OS/X
            debug_level = args.debug[0]
        else:
            # normal case for argparse.ArgumentParser() in Linux
            debug_level = args.debug
    if args.dont_add_perf_headers:
        dont_add_perf_headers = True

    if listen_port:
        run_listener(listen_port, forward_to_addr, dont_add_perf_headers,
                     debug_level)
    elif forward_to_addr:
        run_forwarder(forward_to_addr, dont_add_perf_headers, debug_level)
    else:
        sys.stderr.write("ERROR:\nAt least one option of '-l|--listen' or "
                         "'-f|--forward_to', or both options\n"
                         "(for full-proxy mode), must be given in the "
                         "command line.\n\n")
        # print the usage string of our script (that is the same as the
        # documentation in this script's doctring)
        sys.stderr.write(pyscript_docstring + "\n")


EPOCH_ORIGIN = datetime(1970, 1, 1)
if __name__ == '__main__':
    main()
