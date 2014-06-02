#!/usr/bin/env python3

#  pylsd - Python Lightswitch Daemon
#
#  Copyright ©2014  Simon Arlott
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

import calendar
import configparser
from datetime import datetime
import hmac
import json
import select
import serial
import socket
import syslog
import traceback

HASHES = ["SHA256"]
LIGHTS = ["L", "R"]
TIMEOUT = 10

config = configparser.ConfigParser()
config['pylsd'] = {}
config.read("config", encoding="ASCII")

SECRET = config['pylsd']['secret'].encode("ASCII")
DEV = config['pylsd']['device']

servers = []
requests = []

syslog.openlog("lightswitch")

for res in socket.getaddrinfo(None, 4094, socket.AF_UNSPEC, socket.SOCK_DGRAM, socket.IPPROTO_UDP, socket.AI_PASSIVE):
	(family, socktype, proto, canonname, sockaddr) = res
	s = socket.socket(family, socktype, proto)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	if family == socket.AF_INET6:
		s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
	s.setblocking(False)
	s.bind(sockaddr)
	servers.append(s)


def authorise(data):
	try:
		message = json.loads(data.decode("UTF-8"))
	except ValueError:
		return None

	hash = str(message.get("hash", ""))
	digest_act = str(message.get("digest", ""))
	request = message.get("request", "")

	if not hash in HASHES:
		return None

	digest_exp = hmac.new(SECRET, request.encode("UTF-8"), digestmod=hash).hexdigest()
	if not hmac.compare_digest(digest_act, digest_exp):
		return None

	try:
		request = json.loads(request)
	except ValueError:
		return None

	return request


def validate(request):
	global requests

	if not request:
		return None

	request["ts"] = int(request.get("ts", 0))
	request["light"] = str(request.get("light", ""))

	if request in requests:
		return None

	now = calendar.timegm(datetime.utcnow().timetuple())

	if abs(now - request["ts"]) > TIMEOUT:
		return None

	requests = list(filter(lambda x: abs(now - x["ts"]) <= TIMEOUT, requests))
	requests.append(request)

	return request


def process(data, address):
	request = validate(authorise(data))

	if not request:
		return

	if request["light"] in LIGHTS:
		switch(request["light"])


def switch(light):
	try:
		s = serial.Serial(DEV, baudrate=115200, writeTimeout=0)
		syslog.syslog("toggle " + light)
		s.write(light.encode("ASCII"))
		s.close()
	except:
		syslog.syslog("device missing")
		traceback.print_exc()

while servers:
	for s in select.select(servers, [], [])[0]:
		(data, address) = s.recvfrom(1024)
		process(data, address)

syslog.closelog()
