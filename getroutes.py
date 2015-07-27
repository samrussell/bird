#!/usr/bin/python
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
