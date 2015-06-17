#!/usr/bin/env python3

#  pylsd - Python Lightswitch Request
#
#  Copyright ©2014-2015  Simon Arlott
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import calendar
import configparser
from datetime import datetime
import hmac
import json
import select
import socket
import sys
import uuid

HASH = "SHA256"

config = configparser.ConfigParser()
config["pylsr"] = {}
config.read("config", encoding="ASCII")

SECRET = config["pylsr"]["secret"].encode("ASCII")

parser = argparse.ArgumentParser()
parser.add_argument("node", action="store", metavar="NODE", help="Node to send to")
parser.add_argument("light", action="store", metavar="LIGHT", choices=["L", "C", "R"], help="Light to switch")
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
