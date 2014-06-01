#!/usr/bin/env python3

import argparse
import calendar
from datetime import datetime
import hmac
import json
import select
import socket
import sys
import uuid

SECRET = b"gorKq8oR4oi4ifeIvfjTcZ8_8tPdhACU3ZsrFty4HKd9kwpILuzPB6DAxo9M026o"
HASH = "SHA256"

parser = argparse.ArgumentParser()
parser.add_argument('node', action="store", metavar="NODE", help="Node to send to")
parser.add_argument('light', action="store", metavar="LIGHT", choices=["L", "R"], help="Light to switch")
args = parser.parse_args()

request = json.dumps({
	"ts": calendar.timegm(datetime.utcnow().timetuple()),
	"nonce": uuid.uuid4().hex,
	"light": args.light
})

message = json.dumps({
	"request": request,
	"hash": HASH,
	"digest": hmac.new(SECRET, request.encode("UTF-8"), digestmod=HASH).hexdigest()
}).encode("UTF-8")

for res in socket.getaddrinfo(sys.argv[1], 4094, socket.AF_UNSPEC, socket.SOCK_DGRAM, socket.IPPROTO_UDP):
	(family, socktype, proto, canonname, sockaddr) = res
	s = socket.socket(family, socktype, proto)
	s.sendto(message, sockaddr)
