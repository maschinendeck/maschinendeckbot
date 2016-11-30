#!/usr/bin/env python
# -*- coding: utf-8 -*-

# IRC bot for keeping the topic of a channel updated with the open/closed
# state of a hackerspace.
#

# If you're making a new release, make sure you keep this version in sync
# with debian/changelog or the package build will fail and call you names.
# Just kidding, it's very polite.
__version__ = "0.1.2"

import ConfigParser
import argparse
import logging
import logging.handlers
import urllib2
import signal
import ircbot
import irclib
import socket
import time
import json
import sys
import grp
import pwd
import os
import paho.mqtt.client as mqtt
import random
import time

class Bot(ircbot.SingleServerIRCBot):
   # The last open/closed/etc state we knew.
   state = None

   # Timestamp for the last successful check.
   last_successful_check = None

   clients_total = -1
   clients_wifi = -1

   cooldown_timestamp = 0
   cooldown_count = 0

   def __init__(self, args, config):
      ircbot.SingleServerIRCBot.__init__(self, [(config.get('irc', 'server'), config.getint('irc', 'port'))], config.get('irc', 'nickname'), config.get('irc', 'name'))

      self.config = config

   def on_nicknameinuse(self, connection, event):
      logging.error("Nick %s in use, retrying in %s" % (connection.get_nickname(), self.config.get('irc', 'reconnect_interval')))
      self.disconnect()

   def on_welcome(self, connection, event):
      logging.info("Waiting for NickServ challenge from %s" % (self.config.get('ircnetwork', 'nickserv_addr')))

   def on_privnotice(self, connection, event):
      logging.debug("%s: %s" % (event.source(), event.arguments()))

      # If we get a notice from nickserv...
      if event.source() == self.config.get('ircnetwork', 'nickserv_addr'):

         # ... that asks us to identify, send our password.
         if event.arguments()[0].startswith(self.config.get('ircnetwork', 'nickserv_challenge')):
            logging.info("Got NickServ challenge, identifying...")
            connection.privmsg(self.config.get('ircnetwork', 'nickserv_nick'), "IDENTIFY %s" % self.config.get('irc', 'nickserv_password'))

         # ... telling us our password was accepted, start doing stuff.
         elif event.arguments()[0].startswith(self.config.get('ircnetwork', 'nickserv_success')):
            logging.info("NickServ is satisfied")
       
            # Join the channel in the config, but only if we're supposed to.
            if self.config.getboolean('irc', 'join_channel'):
               logging.info("Joining %s" % self.config.get('irc', 'channel'))
               connection.join(self.config.get('irc', 'channel'))

            # Start periodically checking the open/closed state.
            self.check_state_init()

   def on_pubmsg(self, connection, event):
      message = event.arguments()[0].strip()
      logging.debug("got message %s"%(message))
      parts = message.split(" ")
      if "!raum" in parts or "!clients" in parts or "!help" in parts or "!ofen" in parts or "!raumstatus" in parts:
         now = time.time()
         self.cooldown_count -= 1
         if now > self.cooldown_timestamp + 60*5:
            self.cooldown_timestamp = now
            self.cooldown_count = 5

         if self.cooldown_count == 0:
            self.connection.privmsg(self.config.get('irc', 'channel'), "zu viel Spam hier, ich bin mal fuer 5 Minuten ruhig.")
            logging.debug("engaging cooldown")
         
         if self.cooldown_count < 1:
            return

         if "!raum" in parts or "!raumstatus" in parts:
            state = "(that should never happen)"
            if self.state == True:
               state = "offen"
            elif self.state == False:
               state = "geschlossen"
            elif self.state == None:
               state = "habe seit botstart keinen MQTT-Raumstatus erhalten"
   
            if random.randrange(1,100) > 95:
               state = "%s und sauber" % state
   
            self.connection.privmsg(self.config.get('irc', 'channel'), "raumstatus: %s"%state)
   
         elif "!clients" in parts:
            if self.clients_total == -1 and self.clients_wifi == -1:
                self.connection.privmsg(self.config.get('irc', 'channel'), "clientzahl ist aktuell nicht verfuegbar")
            elif self.clients_total == -1:
                self.connection.privmsg(self.config.get('irc', 'channel'), "aktuell sind %s wlan-clients verbunden"%self.clients_wifi)
            elif self.clients_wifi == -1:
                self.connection.privmsg(self.config.get('irc', 'channel'), "aktuell sind %s clients verbunden"%self.clients_total)
            else:
                self.connection.privmsg(self.config.get('irc', 'channel'), "aktuell sind %s wlan-clients und %s lan-clients verbunden"%(self.clients_wifi, self.clients_total - self.clients_wifi))

         elif "!ofen" in parts:
	    self.connection.privmsg(self.config.get('irc', 'channel'), "Weiß ich nicht. Löte mir bitte etwas Sensorik, die das erfasst")
   
         elif "!help" in parts:
            self.connection.privmsg(self.config.get('irc', 'channel'), "Kommandos: !help, !clients, !raum und sobald jemand das gebaut hat !ofen")


   def on_message(self, client, userdata, msg):
      logging.debug("got on topic %s message %s" % (msg.topic, msg.payload));
      if msg.topic == "/maschinendeck/raum/status":
         if msg.payload == "open":
            self.state = True
            if not msg.retain:
              if random.randrange(1,100) > 95:
                self.connection.privmsg(self.config.get('irc', 'channel'), "Der Raum ist jetzt offen und dreckig.")
              else:
                self.connection.privmsg(self.config.get('irc', 'channel'), "Der Raum ist jetzt offen.")
         elif msg.payload == "closed":
            self.state = False
            if not msg.retain:
              if not msg.retain:
                self.connection.privmsg(self.config.get('irc', 'channel'), "Der Raum ist jetzt geschlossen und dreckig.")
              else:
                self.connection.privmsg(self.config.get('irc', 'channel'), "Der Raum ist jetzt geschlossen.")
         else:
            if not msg.retain:
              self.connection.privmsg(self.config.get('irc', 'channel'), "Der Raum ist gerade verschwunden.")
            logging.info("invalid message received. setting state to None")
            self.state = None
         self.check_state()

      elif msg.topic == "/maschinendeck/wiki/edit":
          logging.info("got edit on wiki")
          try:
             editInfo = json.loads(msg.payload)
          except ValueError:
             logging.error("error decoding /maschinendeck/wiki/edit-JSON")
             return

          if editInfo["isMinor"]:
             logging.info("ignore minor edit")
          else:
             self.connection.privmsg(self.config.get('irc', 'channel'), (u"wiki: '%s' on https://wiki.maschinendeck.org/wiki/%s by %s (diff https://wiki.maschinendeck.org/w/index.php?diff=%s )" % (
                editInfo["summary"],
                editInfo["article"]["mTitle"]["mUrlform"],
                editInfo["user"]["mName"],
		editInfo["article"]["mLatest"]
             )).encode(encoding='utf8'))

      elif msg.topic == "/maschinendeck/raum/clients":
         logging.debug("got clientcount")
         try:
            clientCount = json.loads(msg.payload)
         except ValueError:
            logging.error("error decoding /maschinendeck/raum/clients-JSON")
            self.clients_total = -1
            self.clients_wifi = -1
            return

         if "total" in clientCount:
            self.clients_total = clientCount['total']
         else:
            self.clients_total = -1

         if "wireless" in clientCount:
            self.clients_wifi = clientCount['wireless']
         else:
            self.clients_wifi = -1
        
 

   def check_state_init(self):
      logging.info("Connecting to MQTT")
      client = mqtt.Client()
      client.on_connect = self.on_connect
      client.on_message = self.on_message
      client.connect_async(config.get('mqtt', 'host'), config.getint('mqtt', 'port'), config.getint('mqtt', 'keepalive'))
      client.loop_start()
    
   def on_connect(self, client, userdata, flags, rc):
      logging.info("Connected with result code " + str(rc))

      client.subscribe("/maschinendeck/raum/status")
      client.subscribe("/maschinendeck/wiki/edit")
      client.subscribe("/maschinendeck/raum/clients")

   def check_state(self):
      """Request the current open/closed state from the status URL in the config."""
      logging.debug("Checking open/closed state...")
     
      if self.state in [True, False]:
         self.last_successful_check = time.time()
      elif self.last_successful_check is not None and (time.time() - self.last_successful_check) < self.config.getint('status', 'error_grace_period'):
         logging.info("Couldn't check state, but within error_grace_period time so ignoring this status for now.")
         return

      # The channel topic might need updating. Retrieve the current topic
      # with a LIST command.
      logging.debug("Listing channels to get the topic of %s" % self.config.get('irc', 'channel'))
      try:
         self.connection.list([self.config.get('irc', 'channel')])
      except Exception, ex:
         logging.warning("Unable to list channels to get current topic, state check failed. (%s)" % ex)
         self.disconnect()

   def on_list(self, connection, event):
      """Receives each result from a LIST command."""
      logging.debug("Got channel list item: %s" % event.arguments())
      (channel, usercount, current_topic) = event.arguments()

      # If the result channel matches the channel we're supposed to operate
      # on, try to set new topic text.
      if channel == self.config.get('irc', 'channel'):
         self.set_new_text(channel, current_topic)
      
   def set_new_text(self, channel, current_topic, force_text = None):
      """Given a channel and the current topic text, tries to update the topic based on the value of self.state."""

      # Load the texts from the config and strip double quote characters from the ends.
      texts = dict(map(lambda (k, v): (k, v.strip('"')), self.config.items('statustext')))

      texts[True] = self.config.get('statustext', 'open').strip('"')
      texts[False] = self.config.get('statustext', 'closed').strip('"')
      texts[None] = self.config.get('statustext', 'error').strip('"')

      # Allow the caller to specify the text that should be in the topic.
      if force_text is not None:
         correct_text = force_text
      else:
         # If not, try to look up the text that should be in the topic based on
         # self.state, while handling config sloppiness.
         try:
            correct_text = texts[self.state]
         except KeyError, ex:
            logging.error("State is '%s' but there is no entry in the statustext section of the config for that." % self.state)
            try:
               correct_text = texts["error"]
            except KeyError:
               logging.error("There's no 'error' state in the config either, argh!")
               correct_text = texts[None]
      
      # If the topic doesn't start with the correct state text...
      if not current_topic.startswith(correct_text):

         # Attempt to clean any recognised old state text out of the topic.
         for (state, text) in texts.items():
            if current_topic.startswith(text):
               current_topic = current_topic[len(text):]

         # Set the new state into the topic.
         self.set_topic(correct_text + current_topic)

   def set_topic(self, new_topic):
      """Asks ChanServ to set a new topic"""
      logging.info("Setting new topic for %s: %s" % (self.config.get('irc', 'channel'), new_topic))
      self.connection.privmsg(self.config.get('ircnetwork', 'chanserv_nick'), "TOPIC %s %s" % (self.config.get('irc', 'channel'), new_topic))

if __name__ == '__main__':
   parser = argparse.ArgumentParser(description = 'Checks the open/closed state of a hackerspace and tries to keep the topic of an IRC channel updated.')
   parser.add_argument('-d', dest = 'daemonise', action = 'store_const', const = True, default = False, help = 'Become a daemon.')
   parser.add_argument('-c', dest = 'config_path', action = 'store', default = '/etc/sesamebot.conf', help = 'Path to config file.')
   parser.add_argument('-p', dest = 'pidfile', action = 'store', default = '/var/run/sesamebot.pid', help = 'Path to pid file.')
   args = parser.parse_args()
   
   # Log to syslog or stderr.
   logger = logging.getLogger()
   if args.daemonise:
      logger.setLevel(logging.INFO)
      handler = logging.handlers.SysLogHandler(address = '/dev/log')
   else:
      logger.setLevel(logging.DEBUG)
      handler = logging.StreamHandler() # Writes to stderr by default
   handler.setFormatter(logging.Formatter('sesamebot[%(process)d] %(levelname)s %(message)s'))
   logger.addHandler(handler)

   # Load config
   logging.info("Loading config from %s" % args.config_path)
   config = ConfigParser.ConfigParser()
   try:
      config.readfp(open(args.config_path))
   except IOError, ex:
      logging.error("Failed to open config at %s: %s" % (args.config_path, ex))
      raise SystemExit(1)

   # Let Meatgrinder do some more startup stuff
   bot = Bot(args, config)

   # Add SIGTERM handling
   def _sighandler(signum, frame):
      global bot
      if signum == 15:
         logging.warning("SIGTERM received, exiting...")
         bot.disconnect()

   signal.signal(signal.SIGTERM, _sighandler)

   # Set the cwd to / to avoid keeping parts of the tree 'busy' unnecessarily
   if args.daemonise:
      os.chdir("/")

   # Open pidfile
   if args.daemonise:
      try:
         pidfile = open(args.pidfile, "w")
      except Exception, ex:
         logging.error("Could not open %s for writing: %s" % (args.pidfile, ex))
         raise SystemExit(1)

   # Drop privs
   if args.daemonise and config.getboolean('main', 'drop_privs'):
      try:
         os.setgid(grp.getgrnam(config.get('main', 'group')).gr_gid)
         os.setuid(pwd.getpwnam(config.get('main', 'user')).pw_uid)
      except OSError, ex:
         logging.error("Could not drop privs to %s.%s: %s" % (config.get('main', 'user'), config.get('main', 'group'), ex))

   # Double fork to detach from controlling terminal and ensure we can't ever reclaim one.
   if args.daemonise:
      if os.fork() != 0:
         raise SystemExit(0)
      if os.fork() != 0:
         raise SystemExit(0)

   # Close FDs
   if args.daemonise:
      sys.stdin.close()
      sys.stdout.close()
      sys.stderr.close()

   # Write to pidfile and close it.
   if args.daemonise:
      try:
         pidfile.write(str(os.getpid()))
         pidfile.close()
      except Exception, ex:
         logging.error("Could not write pid to %s: %s" % (args.pidfile, ex))
         # It'd be nice to die here, but this is after we have detached from the
         # terminal. It'd be rude to just go missing.

   # Blocks forever.
   try:
      bot.start()
   except socket.error, ex:
      if ex.errno == 4: # Interrupted system call
         # irclib might have a bug where it can't deal with socket reads being
         # interrupted by signals. TODO Look into this a little deeper.
         pass
   except Exception, ex:
      logging.exception("Dying due to unhandled exception.")

   logging.warning("Exited")
