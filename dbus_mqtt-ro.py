#!/usr/bin/python -u
# -*- coding: utf-8 -*-
import argparse
import dbus
import json
import gobject
import logging
import os
import sys
from time import time
import traceback
import signal
from dbus.mainloop.glib import DBusGMainLoop
from lxml import etree
from collections import OrderedDict

# victron dbus-mqtt
AppDir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(1, os.path.join(AppDir,'dbus-mqtt'))
import dbus_mqtt


SoftwareVersion = '00.1'


class DbusMqtt_ro(dbus_mqtt.DbusMqtt) :
	def __init__(self, mqtt_server=None, ca_cert=None, user=None, passwd=None, dbus_address=None
				,topic_prefix = False,mqtt_retain = False,mqtt_lwt = True): 
		
		##LWT Topic
		if mqtt_lwt:
			self.lwt_topic = '{}/LWT'.format(dbus_mqtt.get_vrm_portal_id());		
		else:
			self.lwt_topic = ''
			
		self._topic_prefix = topic_prefix
		self._use_json_values = False
		
		
		##Init supper
		super(DbusMqtt_ro, self).__init__(mqtt_server=mqtt_server, ca_cert=ca_cert, user=user,
		passwd=passwd, dbus_address=dbus_address		
		)
		
	def stop(self):
		print "Cleaning up"
		#print self._client
		self._publish_all(reset=True)
		

	def _init_mqtt(self):
		
		if self.lwt_topic:
			self._client.will_set(self._topic_prefix+self.lwt_topic,payload="Offline")

		try:
			logging.info('[Init] Connecting to local broker')
			if self._mqtt_user is not None and self._mqtt_passwd is not None:
				self._client.username_pw_set(self._mqtt_user, self._mqtt_passwd)
			if self._ca_cert is None:
				self._client.connect(self._mqtt_server, 1883, 60)
			else:
				self._client.tls_set(self._ca_cert, cert_reqs=ssl.CERT_REQUIRED)
				self._client.connect(self._mqtt_server, 8883, 60)
			self._init_socket_handlers()
			return False
		except socket.error, e:
			if e.errno == errno.ECONNREFUSED:
				return True
			raise

	def _publish(self, topic, value, reset=False):
		if self._socket_watch is None:
			return
		
		# Publish None when service disappears: the topic will no longer show up when subscribing.
		# Clients which are already subscribed will receive a single message with empty payload.
		# Some clients need value as value, not as json value, so check if set and send correct
		
		if reset:
			payload = None
		elif self._use_json_values:			
			payload = json.dumps(dict(value=value))
		else:
			payload = str(value)	
			
		##Strip the "N"
		topic = topic.replace('N/','')
		
		##Prefix the topic		
		if self._topic_prefix:
			topic = self._topic_prefix + topic	
			topic = topic.replace('//','/')
		
		
		
		# Put it into the queue		
		self.queue[topic] = payload

	def _on_connect(self, client, userdata, dict, rc):
		dbus_mqtt.DbusMqtt._on_connect(self, client, userdata, dict, rc)
		
		logging.info('[Connected] Result code {}'.format(rc))
		##Im online
		if(self.lwt_topic):			
			self._publish(self.lwt_topic,"Online")
		
		# Send all values at once, because values may have changed when we were disconnected.
		self._publish_all()
	   
 

def main():
	parser = argparse.ArgumentParser(description='Publishes values from the D-Bus to an MQTT broker')
	parser.add_argument('-d', '--debug', help='set logging level to debug', action='store_true')
	parser.add_argument('-q', '--mqtt-server', nargs='?', default=None, help='name of the mqtt server')
	parser.add_argument('-u', '--mqtt-user', default=None, help='mqtt user name')
	parser.add_argument('-P', '--mqtt-password', default=None, help='mqtt password')
	parser.add_argument('-c', '--mqtt-certificate', default=None, help='path to CA certificate used for SSL communication')
	parser.add_argument('-b', '--dbus', default=None, help='dbus address')			
	parser.add_argument('-t', '--topic', help='Mqtt topic publish prefix, not used for read / write',default=False)
	parser.add_argument('-Mr', '--mqtt-retain', help='Mqtt Retain Yes/No',default="No")
	parser.add_argument('-LWT', '--mqtt-lwt', help='Mqtt LWT Yes/No',default="Yes")
	
	
	
	args = parser.parse_args()

	print("-------- dbus_mqtt, v{} is starting up --------".format(SoftwareVersion))
	logger = dbus_mqtt.setup_logging(args.debug)

	# This allows us to use gobject code in new threads
	gobject.threads_init()

	mainloop = gobject.MainLoop()
	# Have a mainloop, so we can send/receive asynchronous calls to and from dbus
	DBusGMainLoop(set_as_default=True)
	 
	##keep Alive
	 
	mqtt_retain = False if (args.mqtt_retain.lower() == 'no' or args.mqtt_retain.lower() =='n' or args.mqtt_retain.lower() =='0' or args.mqtt_retain.lower() =='false') else True
	mqtt_lwt = False if (args.mqtt_lwt.lower() == 'no' or args.mqtt_lwt.lower() =='n' or args.mqtt_lwt.lower() =='0' or args.mqtt_lwt.lower() =='false') else True
	topic_prefix = args.topic if args.topic else ''
	
	
	
	handler = DbusMqtt_ro(
		mqtt_server=args.mqtt_server, ca_cert=args.mqtt_certificate, user=args.mqtt_user,
		passwd=args.mqtt_password, dbus_address=args.dbus
		,topic_prefix = topic_prefix
		,mqtt_retain = mqtt_retain,mqtt_lwt = mqtt_lwt
		)

	 
	
	# Handle SIGUSR1 and dump a stack trace
	signal.signal(signal.SIGUSR1, dbus_mqtt.dumpstacks)

	# Start and run the mainloop
	try:
		mainloop.run()
	except KeyboardInterrupt:
		handler.stop()
		pass

if __name__ == '__main__':
	main()
