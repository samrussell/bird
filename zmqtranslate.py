#!/usr/bin/python

import os
import sys
import socket
import argparse
import zmq

parser = argparse.ArgumentParser(description='Pass UNIX socket dumps into zeromq messages')
parser.add_argument('address')
args = parser.parse_args()

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
address = args.address
try:
  os.unlink(address)
except OSError:
  if os.path.exists(address):
    raise
sock.bind(address)
sock.listen(1)

print "bound to socket"

while True:
  connection, client_address = sock.accept()
  print "accepted connection!"
  while True:
    data = connection.recv(4096)
    if not data:
      break
    print data

