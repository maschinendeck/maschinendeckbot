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
 - Debian/Ubuntu package

##Usage##

###From source###

To run the bot from source for evaluating it or debugging it, do this:

$ python src/sesamebot.py -c conf/sesamebot.conf

###From deb package###

\# /etc/init.d/sesamebot (start|stop|status)

##Configuration for Freenode##

 - Register a nick for the bot to use
 - Edit the default configuration, reproduced below
 - Give the bot nick permission to change the topic (+t) for your channel
    /msg chanserv flags #yourchannel yourbot +t

##Configuration##

Example configuration:

    [main]
    drop_privs =   true
    user =         nobody
    group =        nogroup
    
    [irc]
    server =             irc.freenode.net
    port =               6667
    nickname =           yourbot
    name =               A bot for telling you when a hackerspace opens/closes.
    nickserv_password =  yourpassword
    channel =            #yourchannel
    join_channel =       false
    reconnect_interval = 60
    
    [status]
    url =             http://hackerspace.example.com/statusdocument.json
    timeout =         5
    check_interval =  60
    
    [statustext]
    # This controls the text that is inserted at the start of the topic.
    true  = "hackerspace is OPEN | "
    false = "hackerspace is CLOSED | "
    error = "hackerspace is (error, check sesamebot syslog) | "
    
    [ircnetwork]
    # Values correct for Freenode as of February 2012.
    chanserv_nick =      ChanServ
    nickserv_nick =      NickServ
    nickserv_addr =      NickServ!NickServ@services.
    nickserv_challenge = This nickname is registered.
    nickserv_success   = You are now identified for

##TODO##

 - Cleaning up topic before shutting down
 - Putting open/closed time in the topic

--
