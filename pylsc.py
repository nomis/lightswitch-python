#!/usr/bin/env python3

#  pylsd - Python Lightswitch Controller
#
#  Copyright ©2015  Simon Arlott
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

import os
import select
import sys
import syslog
import time
import traceback
from time import monotonic as now


MAX_QUEUED_PULSES = 10
PULSE_ON_TIME = 0.2
PULSE_OFF_TIME = 0.3
(IDLE, PULSE_ON, PULSE_OFF) = range(0, 3)

LED_ON = b"255"
LED_OFF = b"0"
GPIO_ON = b"1"
GPIO_OFF = b"0"

lights = dict([(x,{}) for x in ["L", "C", "R"]])


def log_exc():
	traceback.print_exc()
	try:
		for line in traceback.format_exc().split("\n"):
			syslog.syslog(line)
	except Exception as e:
		traceback.print_exc()


def output(light, value):
	try:
		with open("/etc/pin/lightswitch-led-" + light, "wb") as led:
			led.write(LED_ON if value else LED_OFF)
	except Exception as e:
		log_exc()
	finally:
		try:
			with open("/etc/pin/lightswitch-gpio-" + light, "wb") as gpio:
				gpio.write(GPIO_ON if value else GPIO_OFF)
		except Exception as e:
			log_exc()


def reset():
	print(now(), "reset")

	for (light, data) in lights.items():
		data["pulses"] = 0
		data["total"] = 0
		data["state"] = IDLE
		output(light, False)


def pulse(light):
	if lights[light]["pulses"] < MAX_QUEUED_PULSES:
		lights[light]["pulses"] += 1
		print(now(), light, "++pulses =", lights[light]["pulses"])


def process():
	timeout = None

	def require_timeout(timeout, value):
		if value >= 0 and (timeout is None or timeout > value):
			timeout = value
		return timeout

	for (light, data) in lights.items():
		if not data["pulses"]:
			continue

		if data["state"] == IDLE:
			output(light, True)

			data["ts"] = now()
			data["state"] = PULSE_ON
			print(now(), light, "idle -> pulse_on")

			timeout = require_timeout(timeout, PULSE_ON_TIME)
		elif data["state"] == PULSE_ON:
			elapsed = now() - data["ts"]
			if elapsed >= PULSE_ON_TIME:
				output(light, False)

				data["ts"] = now()
				data["state"] = PULSE_OFF
				print(now(), light, "pulse_on -> pulse_off")

				timeout = require_timeout(timeout, PULSE_OFF_TIME)
			else:
				timeout = require_timeout(timeout, PULSE_ON_TIME - elapsed)
		elif data["state"] == PULSE_OFF:
			elapsed = now() - data["ts"]
			if elapsed >= PULSE_OFF_TIME:
				data["state"] = IDLE
				print(now(), light, "pulse_off -> idle")

				data["pulses"] -= 1
				print(now(), light, "--pulses =", lights[light]["pulses"])

				if data["pulses"]:
					timeout = 0
			else:
				timeout = require_timeout(timeout, PULSE_OFF_TIME - elapsed)

	return timeout


syslog.openlog("lightswitch")

reset()

try:
	STDIN = sys.stdin.fileno()

	while True:
		timeout = process()
		print(now(), "timeout", timeout)

		if select.select([sys.stdin], [], [], timeout)[0]:
			data = os.read(STDIN, 1).decode("ASCII", "replace")
			if data == "":
				raise SystemExit
			elif data in lights:
				pulse(data)
finally:
	reset()

syslog.closelog()
