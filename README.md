#sesamebot#
A reasonably simple IRC bot that is intended to keep an IRC channel topic updated with the open/closed state of a hackerspace.

##Features##

 - Reads a JSON document from a URL and expects to parse a Hackerspace Status API document. (https://hackerspaces.nl/spaceapi/)
 - Maintains custom open/closed text at the beginning of the topic
 - Handles NickServ authentication on connect
 - Handles disconnection/reconnection and reauthentication
 - Uses ChanServ to set topics and LIST to read them, so it doesn't have to occupy the IRC channel or need ops
 - Well-behaved daemon
  - Privilege dropping
  - Logging via syslog
  - Signal handling
  - Simple config file
  - pidfile

##TODO##

 - Debian/Ubuntu package
  - Init script
 - Cleaning up topic before shutting down
 - Putting open/closed time in the topic

--
