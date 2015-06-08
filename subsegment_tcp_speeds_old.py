#!/usr/bin/env python

# We use narrow exception-catching in some places (as in "except select.error
#   ..." and "except ValueError ..." below) but in other places we use
# broad-exception catching (also called bare exception catching) for printing
# context-sensitive help) ___immediately followed by a re-raise of the
# exception___. See:
#
# https://www.python.org/dev/peps/pep-0008/#id42
#    ...
#    A good rule of thumb is to limit use of bare 'except' clauses to two cases:
#    1. If the exception handler will be printing out or logging the traceback;
#    at least the user will be aware that an error has occurred.
#
# https://www.python.org/dev/peps/pep-3151/
#
# pylint: disable=broad-except
# pylint: disable=line-too-long

# **************
# The docstring of this module is large, in difference to code lines that are
# mostly limited to 80 chars in length, because, for the docstring the most
# documentation tends to be the best, according to Donald E. Knuth's 'Literate
# Programming' fable to Steve Job in the early '80s, and Knuth's effort in
# this topic, and also, for lengthy docstrings, most common graphical terminals
# have more than 80 characters-columns.
# 
# The code does try to abide by the 80 characters principle though, it is easier
# to read and to comprehend.
# **************

"""Program for helping to isolate which sub-segment in a network [or proxy host in a network] influences more in the delay of a network transmission.

Formally, it works as chain of network proxies with send measure headers among each proxy in the chain.

Invocation:

     subsegment-speeds.py  [-{t|-timeout} <timeout>]  [-{l|-listen} <listen-addr>]  [-{f|-forward-to} <forward-to-address>]  [-{r|-remove-perf-headers}]

     Command-line arguments:

          -{t|-timeout} <timeout>:       specify the timeout for each operation (default: 10 seconds)


          -{l|-listen} <listen-addr>:    which TCP address:port to listen for incoming packets.
                                         (default: none)

                                        If this option -{l|-listen} is not used, the program will
                                        read from the standard-input as fast as possible, inserting
                                        performance-headers every -{b|-block} bytes of read-data;
                                        the answered-data, in turn, will be printed to stardard-output.


          -{f|-forward-to} <forward-to-address>:         to which TCP address:port to forward the
                                                         input data (default: none)
                                        The input data forwarded is the one read either by the
                                        -{l|-listen} address, or by standard-input if the
                                        -{l|-listen} address is omitted.

                                        If -{f|-forward-to} is omitted, then there will be no
                                        forwarding, and this command invocation will echo-back to the
                                        -{l|-listen} address whatever it receives from it.


          -{s|-stdin-block-size} <std-in-block-size>:    Standard-input block size in bytes
                                                         (default: 512)

                                        If -{l|-listen} is not used, the program will read from
                                        standard-input using the block-size indicated here. These
                                        blocks so read are the ones that are then forwarded from
                                        this program to the next subsegment in the network (if
                                        there is one), or to stdout (if there are no -{f|-forward-to}
                                        address).


          -{r|-remove-perf-headers}:     whether to remove or not existing performance headers in a
                                         packet (default: do not remove performance headers in a packet)


Example:

      This is an example with four hosts making up the chain of communication sub-segments in the
      network, the client A works with (connects to) B, B to C, and C to Z.

      B can be in another co-location or geographically remote in comparison to A, or be an entry
      point with heavy-load to another network, etc. The same applies with C in comparison to B,
      it can be in another co-location or geographically remote in comparison to C, etc; and so
      on in this delay-sensitive computer network.

           source host A:

                    subsegment-tcp-speeds.py  --forward-to  <host-B>:9000

                        In this case, A forwards its standard-input to the proxy at B, and gets
                        its answer (and time-delay stats) from B.

           intermediate host B:

                    subsegment-tcp-speeds.py  --listen  '*:9000'  --forward-to  <host-C>:9000

                        In this case, B forwards its standard-input to the proxy at C, and gets
                        its answer (and time-delay stats) from C.

           intermediate host C:

                    subsegment-tcp-speeds.py  --listen  '*:9000'  --forward-to  <host-Z>:9000

                        In this case, C forwards its standard-input to the proxy at Z, and gets
                        its answer (and time-delay stats) from Z.

           end host Z:

                    subsegment-tcp-speeds.py  --listen  '*:9000'

                        In this case, Z doesn't use a --forward-to option, so it is the end
                        backend which resolves client A's initial request. This script simply
                        echoes back the initial request, so it sends back A's standard-input
                        back to A (and time-delay stats).
"""

import sys
import getopt
import socket
import select
import re
import json
import time
import os
import inspect


def usage():
    """Print the usage of this script, taken from the docstring of the 
    script."""
    current_python_script_pathname = inspect.getfile(inspect.currentframe())
    dummy_pyscript_dirname, pyscript_filename = \
                os.path.split(os.path.abspath(current_python_script_pathname))
    pyscript_filename = os.path.splitext( pyscript_filename )[0] # no extension
    sys.stderr.write("DEBUG: Script-name %s\n" % (pyscript_filename))
    pyscript_metadata = __import__(pyscript_filename)
    pyscript_docstring = pyscript_metadata.__doc__
    # TODO: process the docstring to obtain some sections in it as usage string
    pyscript_usage = pyscript_docstring 
    print pyscript_usage


class Receiver(object):
    """The instance of this class represents the receiver, which can be either:
           1. A listening (incoming connection), xor
           2. Standard-input.
    The data received by this instance is the one that will be forwarded, in
    JSON representation.
    This instance is called the 'receiver' since it is the only source of
    data for this program, although it is given back the answered, reply data
    from the 'forwarder'

    A current difference between the Receiver and the Forwarder classes 
    (Forwarder is below) is that the Receiver annotates the JSON object with the
    local-variables (e.g. the local timestamp at this hop), whereas the 
    Forwarder does not annotate the JSON object in principle (although there can
    be situations where both sides, the receiver and the forwarder of this same
    script, should annotate the JSON object each independently of the other)."""

    def __init__(self, stdinp_block_size, listening_address=None, \
		 disable_pkt_annotations=False):
        # defaults:
        self.input_fd = sys.stdin.fileno()  # standard-input
        self.stdinp_block_size = 512
        self.listening_socket = None
        self.receiving_socket = None
        self._associated_file = None
        self._input_eof = False

        # Disable local annotations inside the packet about timestamps and
        # delays recorded in this receiver. (Ie., this receiver will not add its
        # own local measures inside the packet.)
        self.disable_pkt_annotations = disable_pkt_annotations

        if listening_address is None:
            # no listening address to listen to, so this receiver should read
            # instead from standard-input
            self.stdinp_block_size = stdinp_block_size
        else:
            self.input_fd = None   # it is assigned in be self.accept()
            try:
                address, port = listening_address.split(":")
                if address == "*":
                    address = "0.0.0.0"
                list_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                list_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                list_sock.bind((address, int(port)))
                list_sock.listen(1)
            except Exception as an_exc:    # generic Exception will be re-raised
                sys.stderr.write("Error at line %d while listening at addr %s."
                                 " Exception type is: %s\n" % \
                      (sys.exc_info()[-1].tb_lineno, listening_address, an_exc))
                list_sock.close()
                raise
            else:
                self.listening_socket = list_sock


    def accept(self):
        """This is to accept a new incoming connection at
        'self.listening_socket', if there is one: otherwise, if the
        input is by standard-input, this method succeeds and returns
        immediately."""

        if self.listening_socket is None:
            # There is no listening-socket, because this listener had been
            # constructed as to read from the standard input.
            # We already have from the object constructor:
            #       self.input_fd = 0   # standard-input
            # that is the default
            pass
        else:
            client, dummy_address = self.listening_socket.accept()
            self._associated_file = client.makefile('rw')  # use only when setblocking(1)
            client.setblocking(0)
            self.receiving_socket = client
            self.input_fd = client.fileno()


    def close(self):
        """Close the sockets."""

        try:
            if self.receiving_socket is not None:
                self._associated_file.close()
                self.receiving_socket.close()
            if self.listening_socket is not None:
                self.listening_socket.close()
        except Exception as an_exc:    # generic Exception will be re-raised
            sys.stderr.write("Error at line %d while closing listening socket."
                             " Exception type is: %s\n" % \
                               (sys.exc_info()[-1].tb_lineno, an_exc))
            raise


    def _receiver_annotate_fieldname(self):
        """This is the field-name in the JSON structure with which
           this receiver mark the JSON structure with the timestamp
           it has when first receiving it (in the method receive()
           below) and lastly when echoing-it back (in the method
           send() below).

           In other words, as the network data passes through
           different hosts/proxies (each adding a field-name with its
           timestamp to the data), then this method here is to
           generate an Universal UID (UUID) as such field-name
           with which the proxy stamps its time.

           Other field-names for the JSON structure are possible,
           e.g., with more information, as also putting the forwarder
           in the field-name."""

        my_host_domain_name = socket.getfqdn()
        # Take all the DNS non letters or digits characters and
        # transform them into "_"
        my_field_host_dom_n = re.sub(r"[^a-zA-Z0-9]", "_", my_host_domain_name)

        if self.listening_socket is not None:
            listen_address, port = self.listening_socket.getsockname()
            my_field_listen_addr = re.sub(r"[^a-zA-Z0-9]", "_", listen_address)
            json_tstamp_fieldname_uuid = "X_My_Annotation_%s%s%d" % \
                              (my_field_host_dom_n, my_field_listen_addr, port)
            return json_tstamp_fieldname_uuid
        else:
            json_tstamp_fieldname_uuid = "X_My_Annotation_std_input_%s" % \
                                                          (my_field_host_dom_n)
            return json_tstamp_fieldname_uuid


    def _receiver_value_to_annotate(self):
        """What value to annotate in the data by passing through this proxy.
           We just annotate only the current time in this proxy."""
        if not self.disable_pkt_annotations:
            epoch_in_millis = time.time()
            return str(epoch_in_millis)
        else:
            return ''  # Because the local-annotations are disabled at this hop


    def receive(self):
        sys.stderr.write("DEBUG: Receiving in the receiver\n")
        # annotate the incoming object adding a new field with this receiver
        # time-stamp and its timestamp
        incoming_tstamp_value = self._receiver_value_to_annotate()
        field_name = self._receiver_annotate_fieldname()
        incoming_object = None
        if self.receiving_socket is not None:
            # we need to read from the receiving socket a full json object
            sys.stderr.write("DEBUG: Setting recv-socket back to blocking to read from sock-file\n")
            self.receiving_socket.setblocking(1)
            incoming_object = json.load(self._associated_file)
            sys.stderr.write("DEBUG: Setting recv sockt back to non-blocking\n")
            self.receiving_socket.setblocking(0)
            sys.stderr.write("DEBUG: Just read: incoming_object=%s\n" % (str(incoming_object)))
            if isinstance(incoming_object, dict) and \
               not self.disable_pkt_annotations:
                # annotate the incoming object if it is a dict, otherwise don't
                incoming_object[field_name] = incoming_tstamp_value
        else:
            stdin_fd = sys.stdin.fileno()
            if (self.input_fd is not None) and (self.input_fd == stdin_fd):
                # we read from standard-input
                sys.stderr.write("DEBUG: Receiving in receiver from std-inpt\n")
                input_chunks_list = []
                accumulated_bytes_read = 0
                while accumulated_bytes_read < self.stdinp_block_size:
                    chunk = sys.stdin.read(self.stdinp_block_size - \
					    accumulated_bytes_read)
                    sys.stderr.write("DEBUG: Just read stdin: s=%s\n" % (chunk))
                    if chunk == "":
                        # reached the state of EOF in this input fdescript
                        self._input_eof = True
                        break
                    else:
                        input_chunks_list.append(chunk)
                        accumulated_bytes_read += len(chunk)

                data = ''.join(input_chunks_list)
                sys.stderr.write("DEBUG: Just finished reading a block " \
                                 "from stdin: %s\n" % (str(data)))
                # always annotate the incoming line, creating a dictionary
                incoming_object = {}
                if not self.disable_pkt_annotations:
                    incoming_object[field_name] = incoming_tstamp_value
                incoming_object['raw_line'] = data
            else:
                sys.stderr.write("Error at line %d trying to read from " \
                          " receiver but receiver doesn't have an accepted " \
                          " socket connection nor the receiver is stdin\n" % \
                          (sys.exc_info()[-1].tb_lineno))
                raise RuntimeError("Trying to read from receiver but receiver" \
                          " doesn't have an accepted socket connection nor " \
                          " the receiver is standard-input")
        return incoming_object


    def send(self, data_back_to_receiver):
        """Send the data back to the initial sender. If the initial sender
        had been to read from standard-input (ie., no self.receiving_socket),
        then this method prints the received data back to standard-output.

        Before sending the data back, this method updates the annotations in
        the parameter 'data_back_to_receiver' with the local measures in this
        proxy, if it has been asked to do so in by
        'not self.disable_pkt_annotations'.

        If this method has to print the data back to standard-output (ie.,
        this proxy had been the initial origin of all the network path by
        reading from standard-input), then this method also prints to stderr
        all the annotations recorded inside 'data_back_to_receiver' by all
        other proxies later visited during the network path or loop. (Note:
        the report in this paragraph is independent of the option
        self.disable_pkt_annotations which __disables the annotation of
        measures__ at this proxy, but does not disable the __reporting of
        collected annotations by other proxies visited in the path__.
        Perhaps an option independent to self.disable_pkt_annotations to
        explicitly disable this report is necessary. Leaving this option
        off this first version because is not difficult to add, and probably,
        a redirection of stderr to a file or to /dev/null be enough for this
        first version of the script: ie., this first version will always
        report accumulated annotations by all the proxies in the network
        path, if these annotations exist inside 'data_back_to_receiver'."""

        # annotate the incoming data before sending it back, adding a new field
        # with this receiver time-stamp and its timestamp
        if isinstance(data_back_to_receiver, dict) and \
            not self.disable_pkt_annotations:
            # This receiver has requested to locally annotate the visiting
            # packet. Get which local value and local field name to annotate
            # with.
            new_tstamp_value = self._receiver_value_to_annotate()
            note_field_name = self._receiver_annotate_fieldname()

            # See if it was annotated by the receive() method above with
            # the key [note_field_name] in the dictionary data_back_to_receiver
            if note_field_name in data_back_to_receiver:
                # note_field_name was already annotated in the dict by receive()
                # Annotate it again here in send() with the delay between
                # send() and the original receive() of this dict
                old_note_by_receive = data_back_to_receiver[note_field_name]
                try:
                    # this float(<from-string>) conversion could raise an except
                    delay = float(new_tstamp_value) - float(old_note_by_receive)

                    new_note_by_send = "{} {} ({})".format(old_note_by_receive,
	    					           new_tstamp_value,
	    					           delay)
                    # replace the old, partial annotation by receive() with new
                    # one with the delay in send()
                    data_back_to_receiver[note_field_name] = new_note_by_send
                except ValueError as an_exc:
                    # the float(<from-string>) conversion did raise an exception
                    # so this send() couldn't find delay to re-annotate with.
                    # What to do? Delete the old (partial) annotation by
                    # receive() that only has the original tstamp? or leave it?
                    #
                    # del data_back_to_receiver[note_field_name]
                    #
                    # report the conversion error and continue processing
                    sys.stderr.write("Error at line %d while finding delay. " \
                                      "Object-annotations were: %s and %s. " \
                                      "Exception type is: %s\n" % \
                                      (sys.exc_info()[-1].tb_lineno, \
				       old_note_by_receive, \
				       new_tstamp_value, an_exc))

        if self.receiving_socket is not None:
            # send the data back to the receiving socket, from which it had
            # been received
            self.receiving_socket.setblocking(1)
            json.dump(data_back_to_receiver, self._associated_file)
            self.receiving_socket.setblocking(0)
        else:
            # there had not been a receiving socket, but the data had been
            # read from stdin, so we print it to stdout
            if isinstance(data_back_to_receiver, dict):
                # print to std-error all the annotations that were recorded by
                # proxies in this data (including this proxy itself just before
                # printing to standard-output)
                for k in data_back_to_receiver:
                    if k.startswith("X_My_Annotation_"):
                        sys.stderr.write("Visited %s at %s\n", k,
					  data_back_to_receiver[k])
                        del data_back_to_receiver[k]   # remove the annotation

            # Print the data to standard-output (the annotations were printed to
            # standard-error just above)
            if isinstance(data_back_to_receiver, dict) and \
                'raw_line' in data_back_to_receiver:
                # only print the 'raw_line' key (see receive() method above)
                sys.stdout.write(str(data_back_to_receiver['raw_line']))
                return
            sys.stdout.write(str(data_back_to_receiver))



    def eof(self):
        """This is a property-method around the data-member 'self._input_eof'
        that is set in self.receive() when the eof of the incoming connection
        has been reached in 'self.receiving_socket'.

        TODO: use the @property decorator."""

        return self._input_eof




class Forwarder(object):
    """The instance of this class represents the forwarder, which is always
    a client connection to a socket in another, 'next-hop', receiver.

    The data received by this instance is the one that will be forwarded to
    that 'next-hop', in JSON representation.

    The 'forwarder' object will also read replies from the remote extreme in
    this network segment, which then will be passed back to the 'receiver'
    object in this process.

    A current difference between the Receiver and the Forwarder classes is
    that the former annotates the JSON object with the local-variables (e.g.
    the local timestamp at this hop), whereas the Forwarder does not annotate
    the JSON object in principle (although there can be situations where both
    sides, the receiver and the forwarder of this same script, should
    annotate the JSON object each independently of the other)."""

    def __init__(self, forwarding_address=None):
        """The forwarder object does not immediately connects to
        the next-hop at 'forwarding_address' in the object-
        constructor, but connects only when explicitly requested
        to do so by calling this forwarder object's connect()
        method (below).

        This lazy connection is used in order that the controlling
        script can wait for a connection in the receiver object,
        and only then request the forwarder to connect to its
        next-hop at 'forwarding_address'. (TODO: A downside of this
        approach is that the very first incoming packet from the
        receiver has to wait for the TCP-establishment of the new
        forwarding TCP connection.)"""

        self.forwarding_address = forwarding_address
        self.forwarding_socket = None
        self.input_fd = None


    def connect(self):
        """This is to request the forwarder to establish the TCP connection to
        its next-hop at 'self.forwarding_address'."""

        if self.forwarding_address is None:
            # This forwarder will merely echo-back whatever it receives
            pass
        else:
            forward_to_addr = self.forwarding_address
            try:
                forw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_addr, remote_port = forward_to_addr.split(":")
                forw_sock.connect((remote_addr, int(remote_port)))
                self._associated_file = forw_sock.makefile('rw')
                forw_sock.setblocking(0)
            except Exception as an_exc:    # generic Exception will be re-raised
                sys.stderr.write("Error at line %d while forwarding to "
                                 "address %s. Exception type is: %s\n" % \
                       (sys.exc_info()[-1].tb_lineno, forward_to_addr, an_exc))
                forw_sock.close()
                raise
            else:
                self.forwarding_socket = forw_sock
                self.input_fd = forw_sock.fileno()


    def send(self, data_to_forward):
        """This is to request the forwarder to send an object to its next-hop
        at the connection 'self.forwarding_socket'."""

        sys.stderr.write("DEBUG: Before sending data to forwarding socket: "
                         "data=%s\n" % (str(data_to_forward)))
        if self.forwarding_socket is not None:
            sys.stderr.write("DEBUG: Before json.dumps to forwarding socket\n")
            try:
                self.forwarding_socket.setblocking(1)
                json.dump(data_to_forward, self._associated_file)
                self.forwarding_socket.setblocking(0)
            except Exception as an_exc:    # generic Exception will be re-raised
                sys.stderr.write("Error at line %d while sending data through "
                            "the forwarding socket. Exception type is: %s\n" % \
                            (sys.exc_info()[-1].tb_lineno, an_exc))
                raise
        sys.stderr.write("DEBUG: Returning from sending to forwarding socket\n")


    def receive(self):
        """This is to request the forwarder to receive an object from its
        next-hop at the connection 'self.forwarding_socket'."""

        sys.stderr.write("DEBUG: Receiving data from forwarder\n")
        if self.forwarding_socket is not None:
            try:
                self.forwarding_socket.setblocking(1)
                sys.stderr.write("DEBUG: Loading json objt from forwarding socket\n")
                data = json.load(self._associated_file)
                sys.stderr.write("DEBUG: Setting forwarding sockt back to non-blocking\n")
                self.forwarding_socket.setblocking(0)
            except Exception as an_exc:    # generic Exception will be re-raised
                sys.stderr.write("Error at line %d while receiving data from "
                            "the forwarding socket. Exception type is: %s\n" % \
                            (sys.exc_info()[-1].tb_lineno, an_exc))
                raise
            sys.stderr.write("DEBUG: Received this data from forwarder before "
                             "sending it to the receiver: %s\n" % (str(data)))
            return data
        else:
            sys.stderr.write("Error trying to read from the forwarding socket "
                             "because there is no -{f|-forward-to} address\n")
            raise RuntimeError("Trying to read from the forwarding socket "
                               "because there is no -{f|-forward-to} address")


    def close(self):
        """This is to request the forwarder to close the TCP connection with its
        next-hop in 'self.forwarding_socket'."""

        if self.forwarding_socket is not None:
            try:
                self._associated_file.close()
                self.forwarding_socket.close()
            except Exception as an_exc:    # generic Exception will be re-raised
                sys.stderr.write("Error at line %d while closing forwarding "
                                 "socket. Exception type is: %s\n" % \
                                 (sys.exc_info()[-1].tb_lineno, an_exc))
                raise




### MAIN PROGRAM ###


def main():
    """Main() entry-point to this script."""

    timeout = 10
    stdinp_block_size = 512
    listen_port = None
    forward_to_addr = None
    remove_perf_headers = False

    getopts_short = "ht:l:f:s:r"
    getopts_long = ["help", "timeout=", "listen=", "forward-to=", "stdin-block-size=", "remove-perf-headers"]

    try:
        opts, dummy_remainder = \
                       getopt.getopt(sys.argv[1:], getopts_short, getopts_long)
    except getopt.GetoptError as err:
        print "Error in arguments in the command-line:\n   %s\n" % (str(err))
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-t", "--timeout"):
            timeout = int(arg)
        elif opt in ("-l", "--listen"):
            listen_port = arg
        elif opt in ("-f", "--forward-to"):
            forward_to_addr = arg
        elif opt in ("-s", "--stdin-block-size"):
            stdinp_block_size = int(arg)
        elif opt in ("-r", "--remove-perf-headers"):
            remove_perf_headers = True


    receiver = None
    forwarder = None
    try:
        if forward_to_addr is not None:
            forwarder = Forwarder(forward_to_addr)

        receiver = Receiver(stdinp_block_size, listen_port, remove_perf_headers)
        receiver.accept()
        sys.stderr.write("DEBUG: Receiver just accepted connection\n")
        if forwarder is not None:
            forwarder.connect()
        sys.stderr.write("DEBUG: Forwarder has connected\n")

        inputs = [receiver.input_fd]
        if forwarder is not None:
            inputs.append(forwarder.input_fd)

        while not receiver.eof():

            sys.stderr.write("DEBUG: Before select() with inputs %s\n" % \
                                 (str(inputs)))
            exceptions = inputs   # also check the inputs for exceptions
            try:
                readable_set, dummy_writeable_set, exceptional_set = \
                               select.select(inputs, [], exceptions, timeout)
                # a deep analysis on select(), epoll() and kqueue:
                # www.eecs.berkeley.edu/~sangjin/2012/12/21/epoll-vs-kqueue.html
                #
            except select.error as an_exc:
                sys.stderr.write("Error at line %d while receiving from "
                          "json-object from socket. Exception type is: %s\n" % \
                            (sys.exc_info()[-1].tb_lineno, an_exc))
                raise

            sys.stderr.write("DEBUG: After select(), returning readable_set=" + str(readable_set) + " and exceptional_set=" + str(exceptional_set) +"\n")
            if exceptional_set:
                # the exceptions-set of files has a file with an error
                which_files_excepted = []
                if receiver.input_fd in exceptional_set:
                    which_files_excepted.append("listener")
                if (forwarder is not None) and \
                                (forwarder.input_fd in exceptional_set):
                    which_files_excepted.append("forwarder")
                sys.stderr.write("INFO: This socket(s) '%s' has closed.\n" % \
                                      (' '.join(which_files_excepted)))


            # Read first from forwarder to see if it has answered something
            if (forwarder is not None) and (forwarder.input_fd in readable_set):
                forw_data = forwarder.receive()
                sys.stderr.write("DEBUG: Received this data from forwarder "
                                 "before sending it to the receiver: %s\n" % \
                                    (str(forw_data)))
                receiver.send(forw_data)

            if receiver.input_fd in readable_set:
                sys.stderr.write("DEBUG: Receiving data from receiver\n")
                recv_data = receiver.receive()
                sys.stderr.write("DEBUG: Received this data from receiver "
                                 "before sending it to the forwarder or "
                                 "echoing it back to the receiver: %s\n" % \
                                     (str(recv_data)))
                if forwarder is not None:
                    forwarder.send(recv_data)
                else:
                    # there is no forwarder, so the data just read from
                    # receiver.receive() mustn't be forwarded, but echo-back to
                    # the receiver
                    receiver.send(recv_data)

        receiver.close()
        if forwarder is not None:
            forwarder.close()

    except Exception as an_exc:    # catch generic Exception at main() block
        sys.stderr.write("Main: Exception caught at file " +
                                (sys.exc_info()[2]).tb_frame.f_code.co_filename +
                         " line " + str((sys.exc_info()[2]).tb_lineno)  +
                         ". Exception " + str(sys.exc_info()[0]) + "\n")



if __name__ == '__main__':
    main()

