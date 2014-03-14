#!/usr/bin/env python

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

class Bot(ircbot.SingleServerIRCBot):
   # The last open/closed/etc state we knew.
   state = None

   # Timestamp for the last successful check.
   last_successful_check = None

   def __init__(self, args, config):
      ircbot.SingleServerIRCBot.__init__(self, [(config.get('irc', 'server'), config.getint('irc', 'port'))], config.get('irc', 'nickname'), config.get('irc', 'name'))

      self.config = config

   def on_nicknameinuse(self, connection, event):
      logging.error("Nick %s in use, retrying in %ds" % (connection.get_nickname(), self.config.get('irc', 'reconnect_interval')))
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
            self.check_state_periodic()

   def check_state_periodic(self):
      # Schedule another call to checking the state later.
      self.connection.execute_delayed(self.config.getint('status', 'check_interval'), Bot.check_state_periodic, (self,))

      # Check the open/closed state now.
      self.check_state()

   def check_state(self):
      """Request the current open/closed state from the status URL in the config."""
      logging.debug("Checking open/closed state...")

      # Try to fetch the JSON document specifying whether the hackerspace is open.
      try:
         state_json = urllib2.urlopen(self.config.get('status', 'url'), timeout = self.config.getint('status', 'timeout')).read()
         self.state = json.loads(state_json)['state']['open']
      except:
         self.state = None
         logging.exception("Unable to read open/closed state from %s:" % self.config.get('status', 'url'))
     
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
