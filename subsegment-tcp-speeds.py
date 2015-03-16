#!/usr/bin/env python

import sys, getopt, traceback, os, socket, select, json

usage_string="""Usage: Program for helping to isolate which sub-segment in a network [or proxy host in a network] influences more in the delay of a network transmission.

Formally, it works as chain of network proxies with send measure headers among each proxy in the chain.
Invocation:
     subsegment-speeds.py  [-{t|-timeout} <timeout>]  [-{l|-listen} <listen-addr>]  [-{f|-forward-to} <forward-to-address>]  [-{r|-remove-perf-headers}]

     Command-line arguments:

          -{t|-timeout} <timeout>:	specify the timeout for each operation (default: 10 seconds)

          -{l|-listen} <listen-addr>:	which TCP address:port to listen for incoming packets (default: none)

                                        If this option -{l|-listen} is not used, the program will read from the standard-input as fast as possible, 
                                        inserting performance-headers every -{b|-block} bytes of read-data; the answered-data, in turn, will be printed to stardard-output.
                                        

          -{f|-forward-to} <forward-to-address>:		to which TCP address:port to forward the input data (default: none)
                                        The input data forwarded is the one read either by the -{l|-listen} address, or by standard-input if the -{l|-listen} address is omitted.

                                        If -{f|-forward-to} is omitted, then there will be no forwarding, and this command invocation will echo-back to the -{l|-listen} address 
                                        whatever it receives from it.

          -{s|-stdin-block-size} <std-in-block-size>:	Standard-input block size in bytes (default: 512)
                                                    	If -{l|-listen} is not used, the program will read from standard-input using the block-size indicated here.
                                                    	These blocks so read are the ones that are then forwarded from this program to the next subsegment in the network (if 
                                                    	there is one), or to stdout (if there are no -{f|-forward-to} address).

          -{r|-remove-perf-headers}:	whether to remove or not existing performance headers in a packet (default: do not remove performance headers in a packet)

Example:
      This is an example with four hosts making up the chain of sub-segments in the network, A<->B, B<->C, C<->D:

           source host A:
      
           intermediate host B:

           intermediate host C:

           end host Z:

"""

remove_performance_headers_in_packet = False



class Receiver:

	def __init__(self, stdinp_block_size, listening_address=None ):
		# defaults:
		self.input_fd = sys.stdin.fileno()  # standard-input
		self.stdinp_block_size = 512
		self.listening_socket = None   
		self.receiving_socket = None
		self.input_eof = False

		if listening_address is None:
			# no listening address to listen to, so this receiver should read instead from standard-input
			self.stdinp_block_size = stdinp_block_size
		else:
			self.input_fd = None   # it needs to be accept() first -see next method
			try: 
				address, port = listening_address.split(":")
				if address == "*": address = "0.0.0.0"
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				s.bind(( address, int(port) ))
				s.listen(1)
			except Exception, e:
				sys.stderr.write("Error at line %d while listening at address %s. Exception type is: %s\n" % ( sys.exc_info()[-1].tb_lineno, listening_address, e ) )
				s.close()
				raise
			else: 
				self.listening_socket = s
	 

	def accept(self):
		if self.listening_socket is None:
			# There is no listening-socket, because this listener had been constructed as to read from the standard input
			# We already have from the object constructor:
			#       self.input_fd = 0   # standard-input
			# that is the default
			pass
		else: 
			client, address = self.listening_socket.accept()
			client.setblocking(0)
			self.receiving_socket = client
			self.input_fd = client.fileno()
 

	def close(self):
		try:
			if self.receiving_socket is not None:
				self.receiving_socket.close()
			if self.listening_socket is not None:
				self.listening_socket.close()
		except Exception, e:
			sys.stderr.write("Error at line %d while closing listening socket. Exception type is: %s\n" % ( sys.exc_info()[-1].tb_lineno, e ) )
			raise


	def receive(self):
			data = ""
			if self.receiving_socket is not None:
				# we read from the receiving socket, and we need to read a full object
				self.receiving_socket.setblocking(1)
				# data = util_communication_module.internal_communication_receiv( self.receiving_socket )
				data = json.load( self.receiving_socket )
				self.receiving_socket.setblocking(0)
			else:
				fd = sys.stdin.fileno()
				if ( self.input_fd is not None ) and ( self.input_fd == fd ):
					# we read from standard-input
					# data=""
					while len(data) < self.stdinp_block_size:
						s = sys.stdin.read( self.stdinp_block_size - len(data) )
						if s == "": 
							self.input_eof = True
							break  
                        			data += s
				else:
                        		sys.stderr.write("Error at line %d trying to read from receiver but receiver doesn't have an accepted socket connection nor the receiver is standard-input\n" % ( sys.exc_info()[-1].tb_lineno ) )
                        		raise RuntimeError("Trying to read from receiver but receiver doesn't have an accepted socket connection nor the receiver is standard-input")
			return data

	def send(self, data_back_to_receiver):
			if self.receiving_socket is not None:
				# send the data back to the receiving socket, from which it had been received
				# util_communication_module.internal_communication_send( self.receiving_socket, data_back_to_receiver )
				json_repres = json.dumps( data_back_to_receiver , sort_keys=True, separators=(',', ': '))
				self.receiving_socket.send( json_repres )

			else:
				# there had not been a receiving socket, but the data had been read from stdin, so we print it to stdout 
				sys.stdout.write( str( data_back_to_receiver ) )

	def eof(self):
			return self.input_eof 




class Forwarder:

	def __init__(self, forwarding_address=None):
		
		self.forwarding_address= forwarding_address 
		self.forwarding_socket = None
		

	def connect(self):
		if self.forwarding_address is None:
			# This forwarder will merely echo-back whatever it receives
			pass
		else:
			forw_addr = self.forwarding_address
			try: 
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				remote_addr, remote_port = forward_to_addr.split(":")
				s.connect( (remote_addr, int(remote_port) ) )
				s.setblocking(0)
			except Exception, e: 
				sys.stderr.write("Error at line %d while forwarding to address %s. Exception type is: %s\n" % ( sys.exc_info()[-1].tb_lineno, forw_addr, e ) )
				s.close()
				raise
			else: 
				self.forwarding_socket = s
				self.input_fd = s.fileno()


	def send(self, data_to_forward):
		try:
			if self.forwarding_socket is not None:
				# util_communication_module.internal_communication_send( self.forwarding_socket, data_to_forward )
				json_repres = json.dumps( data_to_forward, sort_keys=True, separators=(',', ': '))
				self.forwarding_socket.send( json_repres )
		except Exception, e:
			sys.stderr.write("Error at line %d while sending data through the forwarding socket. Exception type is: %s\n" % ( sys.exc_info()[-1].tb_lineno, e ) )
			raise


	def receive(self):
		if self.forwarding_socket is not None:
			try:
				# data = util_communication_module.internal_communication_receiv( self.forwarding_socket )
				self.forwarding_socket.setblocking(1)
				data = json.load( self.forwarding_socket )
				self.forwarding_socket.setblocking(0)
			except Exception, e:
				sys.stderr.write("Error at line %d while receiving data from the forwarding socket. Exception type is: %s\n" % ( sys.exc_info()[-1].tb_lineno, e ) )
				raise
			return data
		else:
			sys.stderr.write("Error trying to read from the forwarding socket because there is no -{f|-forward-to} address\n" )
			raise RuntimeError("Trying to read from the forwarding socket because there is no -{f|-forward-to} address")


	def close(self):
		try:
			if self.forwarding_socket is not None:
				self.forwarding_socket.close()
		except Exception, e:
			sys.stderr.write("Error at line %d while closing forwarding socket. Exception type is: %s\n" % ( sys.exc_info()[-1].tb_lineno, e ) )
			raise




### MAIN PROGRAM ###

global receiver
global forwarder

if __name__ == '__main__':

    timeout = 10
    stdinp_block_size = 512
    listen_port = None
    forward_to_addr = None

    try:
        opts, remainder = getopt.getopt( sys.argv[1:], "ht:l:f:s:r", ["help", "timeout=", "listen=", "forward-to=", "stdin-block-size=", "remove-perf-headers" ])
    except getopt.GetoptError as err:
        print "Error in arguments in the command-line:\n      " + str(err) + "\n"
        print usage_string
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print usage_string
            sys.exit()
        elif opt in ("-t", "--timeout"):
            timeout = int( arg )
        elif opt in ("-l", "--listen"):
            listen_port = arg
        elif opt in ("-f", "--forward-to"):
            forward_to_addr = arg
        elif opt in ("-s", "--stdin-block-size"):
            stdinp_block_size = int( arg )
        elif opt in ("-r", "--remove-perf-headers"):
            remove_performance_headers_in_packet = True

    
    if forward_to_addr == "":
	no_more_proxy_performance_forward_chain = True

    receiver= None
    forwarder= None
    try:
	if forward_to_addr is not None: forwarder = Forwarder( forward_to_addr )

    	receiver = Receiver( stdinp_block_size, listen_port )
	receiver.accept()
	if forwarder is not None: forwarder.connect()

	inputs = [ receiver.input_fd ]
	if forwarder is not None: inputs.append( forwarder.input_fd )

	while not receiver.eof():

		exceptions = inputs   # also check the inputs for exceptions
		try:
			readable_set, writeable_set, exceptional_set = select.select( inputs, [], exceptions, timeout )
			# a deep analysis on select(), epoll() and kqueue: http://www.eecs.berkeley.edu/~sangjin/2012/12/21/epoll-vs-kqueue.html
		except select.error, e:
			sys.stderr.write("Error at line %d while receiving from json-object from socket. Exception type is: %s\n" % ( sys.exc_info()[-1].tb_lineno, e ) )
			raise
  
		if exceptional_set:
			# the exceptions-set of files has a file with an error
			file_s = ""
			if receiver.input_fd in exceptional_set: file_s += "listener "
			if ( forwarder is not None ) and ( forwarder.input_fd in exceptional_set ): file_s += "forwarder "
			# sys.stderr.write("INFO: This socket(s) '%s' has closed.\n" % ( file_s ) )


		# Read first from the forwarder to see if the forwarder has answered something
		if ( forwarder is not None ) and ( forwarder.input_fd in readable_set ): 
			forw_data = forwarder.receive() 
			receiver.send( forw_data )

		if receiver.input_fd in readable_set:
			recv_data = receiver.receive()
			if forwarder is not None:
				forwarder.send( recv_data )
			else:
				# there is no forwarder, so the data just read from receiver.receive() must not be forwarded, but echo-back to the receiver
				receiver.send( recv_data )

	receiver.close()
	if forwarder is not None: forwarder.close()

    except Exception, e:
	sys.stderr.write("Main: Exception caught at file " + (sys.exc_info()[2]).tb_frame.f_code.co_filename + " line " + str( (sys.exc_info()[2]).tb_lineno )  + ". Exception " + str( sys.exc_info()[0] ) + "\n")

