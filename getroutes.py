#!/usr/bin/python
#
#      BIRD Route dump client
#
#      (c) 2015 Sam Russell <sam.h.russell@gmail.com>
#
#      Can be freely distributed and used under the terms of the GNU GPL.
#
import zmq

context = zmq.Context()
print "connecting to server"
socket = context.socket(zmq.REQ)
socket.connect("tcp://127.0.0.1:5556")
print "sending data"
socket.send("gary")
message = socket.recv_multipart()
print "Routes:"
print '\n'.join([x for x in message])
