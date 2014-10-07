#!/usr/bin/python
import os
import sys
import socket

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/home/gary/gary.sock")
