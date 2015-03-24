#!/usr/bin/env python


usage_string="""Program for helping to isolate which sub-segment in a network [or proxy host in a network] influences more in the delay of a network transmission.

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


class Receiver(object):
    """The instance of this class represents the receiver, which can be either:
           1. A listening (incoming connection), xor
           2. Standard-input.
    The data received by this instance is the one that will be forwarded, in
    JSON representation.
    This instance is called the 'receiver' since it is the only source of
    data for this program, although it is given back the answered, reply data
    from the 'forwarder'"""

    def __init__(self, stdinp_block_size, listening_address=None):
        # defaults:
        self.input_fd = sys.stdin.fileno()  # standard-input
        self.stdinp_block_size = 512
        self.listening_socket = None
        self.receiving_socket = None
        self.input_eof = False

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
        if self.listening_socket is None:
            # There is no listening-socket, because this listener had been
            # constructed as to read from the standard input.
            # We already have from the object constructor:
            #       self.input_fd = 0   # standard-input
            # that is the default
            pass
        else:
            client, dummy_address = self.listening_socket.accept()
            client.setblocking(0)
            self.receiving_socket = client
            self.input_fd = client.fileno()


    def close(self):
        try:
            if self.receiving_socket is not None:
                self.receiving_socket.close()
            if self.listening_socket is not None:
                self.listening_socket.close()
        except Exception as an_exc:    # generic Exception will be re-raised
            sys.stderr.write("Error at line %d while closing listening socket."
                             " Exception type is: %s\n" % \
                               (sys.exc_info()[-1].tb_lineno, an_exc))
            raise


    def _receiver_tstamp_fieldname(self):
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

        my_host_domain_name = socket.gethostname()
        # Take all the DNS non letters or digits characters and
        # transform them into "_"
        my_field_host_dom_n = re.sub(r"[^a-zA-Z0-9]", "_", my_host_domain_name)

        if self.listening_socket is not None:
            listen_address, port = self.listening_socket.getsockname()
            my_field_listen_addr = re.sub(r"[^a-zA-Z0-9]", "_", listen_address)
            json_tstamp_fieldname_uuid = "X_My_TStamp_%s%s%d" % \
                              (my_field_host_dom_n, my_field_listen_addr, port)
            return json_tstamp_fieldname_uuid
        else:
            json_tstamp_fieldname_uuid = "X_My_TStamp_std_input_%s" % \
                                                          (my_field_host_dom_n)
            return json_tstamp_fieldname_uuid


    def receive(self):
        sys.stderr.write("DEBUG: Receiving in the receiver\n")
        data = ""
        if self.receiving_socket is not None:
            # we need to read from the receiving socket a full json object
            sys.stderr.write("DEBUG: Setting recv-socket back to blocking\n")
            self.receiving_socket.setblocking(1)
            sys.stderr.write("DEBUG: Loading json objt from recv socket\n")
            data = json.load(self.receiving_socket)
            sys.stderr.write("DEBUG: Setting recv sockt back to non-blocking\n")
            self.receiving_socket.setblocking(0)
        else:
            stdin_fd = sys.stdin.fileno()
            if (self.input_fd is not None) and (self.input_fd == stdin_fd):
                # we read from standard-input
                sys.stderr.write("DEBUG: Receiving in receiver from std-inpt\n")
                input_chunks_list = []
                while len(data) < self.stdinp_block_size:
                    chunk = sys.stdin.read(self.stdinp_block_size - len(data))
                    sys.stderr.write("DEBUG: Just read stdin: s=%s\n" % (chunk))
                    if chunk == "":
                        # reached the state of EOF in this input fdescript
                        self.input_eof = True
                        break
                    else:
                        input_chunks_list.append(chunk)

                data = ''.join(input_chunks_list)
                sys.stderr.write("DEBUG: Just finished reading a block "
                                 "from stdin: %s\n" % (str(data)))
            else:
                sys.stderr.write("Error at line %d trying to read from receiver"
                          " but receiver doesn't have an accepted socket"
                          " connection nor the receiver is standard-input\n" % \
                          (sys.exc_info()[-1].tb_lineno))
                raise RuntimeError("Trying to read from receiver but receiver"
                          " doesn't have an accepted socket connection nor "
                          " the receiver is standard-input")
        sys.stderr.write("DEBUG: Before returning: data=%s\n" % (str(data)))
        return data


    def send(self, data_back_to_receiver):
        if self.receiving_socket is not None:
            # send the data back to the receiving socket, from which it had
            # been received
            json_repres = json.dumps(data_back_to_receiver, sort_keys=True)
            self.receiving_socket.send(json_repres)

        else:
            # there had not been a receiving socket, but the data had been
            # read from stdin, so we print it to stdout
            sys.stdout.write(str(data_back_to_receiver))


    def eof(self):
        return self.input_eof




class Forwarder(object):
    """The instance of this class represents the forwarder, which is always
    a client connection to a socket in another network segment.

    The data received by this instance is the one that will be forwarded, in
    JSON representation.

    The 'forwarder' object will also read replies from the remote extreme in
    this network segment, which then will be passed back to the 'receiver'
    object."""

    def __init__(self, forwarding_address=None):

        self.forwarding_address = forwarding_address
        self.forwarding_socket = None


    def connect(self):
        if self.forwarding_address is None:
            # This forwarder will merely echo-back whatever it receives
            pass
        else:
            forward_to_addr = self.forwarding_address
            try:
                forw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_addr, remote_port = forward_to_addr.split(":")
                forw_sock.connect((remote_addr, int(remote_port)))
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
        sys.stderr.write("DEBUG: Before sending data to forwarding socket: "
                         "data=%s\n" % (str(data_to_forward)))
        if self.forwarding_socket is not None:
            sys.stderr.write("DEBUG: Before json.dumps to forwarding socket\n")
            try:
                json_repres = json.dumps(data_to_forward, sort_keys=True)
                self.forwarding_socket.send(json_repres)
            except Exception as an_exc:    # generic Exception will be re-raised
                sys.stderr.write("Error at line %d while sending data through "
                            "the forwarding socket. Exception type is: %s\n" % \
                            (sys.exc_info()[-1].tb_lineno, an_exc))
                raise
        sys.stderr.write("DEBUG: Returning from sending to forwarding socket\n")


    def receive(self):
        sys.stderr.write("DEBUG: Receiving data from forwarder\n")
        if self.forwarding_socket is not None:
            try:
                self.forwarding_socket.setblocking(1)
                data = json.load(self.forwarding_socket)
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
        if self.forwarding_socket is not None:
            try:
                self.forwarding_socket.close()
            except Exception as an_exc:    # generic Exception will be re-raised
                sys.stderr.write("Error at line %d while closing forwarding "
                                 "socket. Exception type is: %s\n" % \
                                 (sys.exc_info()[-1].tb_lineno, an_exc))
                raise




### MAIN PROGRAM ###


def main():

    timeout = 10
    stdinp_block_size = 512
    listen_port = None
    forward_to_addr = None
    remove_perf_headers_in_packet = False

    getopts_short = "ht:l:f:s:r"
    getopts_long = ["help", "timeout=", "listen=", "forward-to=", "stdin-block-size=", "remove-perf-headers"]

    try:
        opts, dummy_remainder = \
                       getopt.getopt(sys.argv[1:], getopts_short, getopts_long)
    except getopt.GetoptError as err:
        print "Error in arguments in the command-line:\n   %s\n" % (str(err))
        print usage_string
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print usage_string
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
            remove_perf_headers_in_packet = True


    receiver = None
    forwarder = None
    try:
        if forward_to_addr is not None:
            forwarder = Forwarder(forward_to_addr)

        receiver = Receiver(stdinp_block_size, listen_port)
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

