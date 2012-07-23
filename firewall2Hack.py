# Copyright 2011 James McCauley & 2012 Aashutosh kalyankar
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
This is an L2 learning switch written directly against the OpenFlow library.
It is derived from one written live for an SDN crash course.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp
from pox.lib.recoco import *
import time
import itertools
import json
import urllib2
import threading


log = core.getLogger()
dictionaryProfiles ={}
TIMEOUT = 25

# We don't want to flood immediately when a switch connects.
FLOOD_DELAY = 5

""" Implemented Policy is a list of 'ids' whose policies are implemented """
implementedPolicy=[]

class LearningSwitch (EventMixin):

    def __init__ (self, connection, transparent):
        # Switch we'll be adding L2 learning switch capabilities to
        self.connection = connection
        self.transparent = transparent

        # Our table
        self.macToPort = {}

        # We want to hear PacketIn messages, so we listen
        self.listenTo(connection)

    #log.debug("Initializing LearningSwitch, transparent=%s",str(self.transparent))

    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch.
        """
        packet = event.parse()

        def flood ():
            """ Floods the packet """
            if event.ofp.buffer_id == -1:
                log.warning("Not flooding unbuffered packet on %s", dpidToStr(event.dpid))
                return
            msg = of.ofp_packet_out()
            if time.time() - self.connection.connect_time > FLOOD_DELAY:
                # Only flood if we've been connected for a little while...
                log.debug("%i: flood %s -> %s", event.dpid, packet.src, packet.dst)
                msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            else:
                pass
                log.info("Holding down flood for %s", dpidToStr(event.dpid))
            msg.buffer_id = event.ofp.buffer_id
            msg.in_port = event.port
            self.connection.send(msg)

        def drop (duration = None):

            """
            Drops this packet and optionally installs a flow to continue
            dropping similar ones for a while
            """
            if duration is not None:
                if not isinstance(duration, tuple):
                    duration = (duration,duration)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)
            elif event.ofp.buffer_id != -1:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)

        self.macToPort[packet.src] = event.port

        def installflow():
            log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet)
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.actions.append(of.ofp_action_output(port = port))
            msg.buffer_id = event.ofp.buffer_id # 6a
            self.connection.send(msg)


        if not self.transparent:
            if packet.type == packet.LLDP_TYPE:
                drop()
                return

        if packet.dst.isMulticast():
            flood()
        else:
            if packet.dst not in self.macToPort:
                log.debug("Port for %s unknown -- flooding" % (packet.dst,))
                flood() # 4a
            else:
                port = self.macToPort[packet.dst]
                if port == event.port: # 5
                    log.warning("Same port for packet from %s -> %s on %s.  Drop." %(packet.src, packet.dst, port), dpidToStr(event.dpid))
                    drop(10)
                    return
                installflow()

class Timer ():
    def __init__(self):
        self.timeout = time.time()+TIMEOUT
    def isExpired (self):
        return time.time() > self.timeout

"""Event Handling in POX fits into the publish/subscribe mechanism.
 Classes wishing to receive events should inherit the EventMixin class"""

class Firewall(Task):

    def __init__(self):
        Task.__init__(self)
        self.sockets = self.get_sockets()
        core.addListerner(pox.core.GoingUpEvent,self.start_event_loop)


    def start_event_loop(self ,event):
        Task.start(self)

    def get_sockets(self):
        return []

    def handle_read_events(self):

        def getDataDB():
            """  Deprecated #### 1) Connect to google database and get data from the database
            2) if id not in the implemented Policy list, implement the policy or else do nothing
            3) parse through dictionary to get all the values
            4) if the policy's profile matches that of a switch. implement the policy
            """
            url = "http://firewallaashu.appspot.com/download"
            try:
                result = urllib2.urlopen(url)
                #print result
                """You must read the file otherwise we get an error"""
                c = result.read()
                d = json.loads(c)
                return d
            except urllib2.URLError, e:
                print (" URL fail -: %s " %(e))
                log.debug(" URL fail")

        def getPolicyToImplement(dictionaryMain):
            """ to Implement is a list of policies in DICTIONARY format that needs to be implemented"""
            toImplement=[]
            """ to Implement is a list of ids in DICTIONARY format that needs to be implemented"""
            toImplementKeys =[]
            for k,adict in dictionaryMain.iteritems():
                if k in implementedPolicy:
                    pass
                else:
                    toImplement.append(adict)
                    toImplementKeys.append(k)
            return toImplement,toImplementKeys



        def blockAction (actions):
            if actions =='block':
                return True

            elif actions == 'allow':
                return False


        def getService(service):
            if service =='http' or service =='ssh':
                pac_type = 0x800

            elif service =='arp':
                pac_type =0x806
            return pac_type


        def interpretPolicy(toImplement):
            # s == toImplement : it is a list of adict && one adict == one flow rule
            # so s contains list of policies to be implemented
            for s in toImplement:
                profile =s['profile']
                srcip=s['srcip']
                dstip=s['dstip']
                actions = s['actions']
                service=s['service']  # http , ssh , arp
                portno=s['port']
                directions = s['directions']

                # get the type of the packet
                pac_type = getService(service)

                if srcip =='any' and dstip =='any':

                    if blockAction(actions):
                        """block all the ip traffic"""
                        msg = of.ofp_flow_mod()
                        """ set a higher priority rule """
                        msg.priority = 100
                        msg.match.dl_type = pac_type
                        self.connection.send(msg)

                else:
                    """ set a medium priority rule """
                    pac_src = srcip
                    pac_dst = dstip

                    if blockAction(actions):
                        msg = of.ofp_flow_mod()
                        msg.priority = 200
                        msg.match.dl_type =pac_type
                        if pac_src != 'any':
                            msg.match.nw_src = pac_src
                        if pac_dst != 'any':
                            msg.match.nw_dst = pac_dst
                        if portno != 'any':
                            if directions =='destination':
                                msg.match.tp_dst = portno
                            elif directions =='source':
                                msg.match.tp_src = portno
                        #self.connection.send(msg)
                        print str(msg)

        data = getDataDB()
        log.debug(" Data successfully received ")

        toImplement, toImplementKeys = getPolicyToImplement(data)
        log.debug("policies to implement fetched")

        if toImplement != [] and toImplementKeys !=[]:
            interpretPolicy(toImplement)
            log.debug("all Policies successfully Implemented")

            for ids in toImplementKeys:
                implementedPolicy.append(ids)
            log.debug("Finished Implementing Policies")
        else:
            log.debug("Policies already Implemented")



    def run (self):
        while core.running:
            rlist,wlist,elist = yield Select(self.sockets, [], [], 3)
            events = []
            for read_sock in rlist:
                if read_sock in self.sockets:
                    events.append(read_sock)

                if events:
                    self.handle_read_events()







    """ ##############  Deprecated ###########################
                msg =of.ofp_flow_mod(command = of.OFPFC_ADD, idle_timeout= of.OFP_FLOW_PERMANENT , hard_timeout=of.OFP_FLOW_PERMANENT,buffer_id=event.ofp.buffer_id,action=of.ofp_action_output(),match=of.ofp_match.from_packet(packet.type= 0x866, packet.tc_dst=0x17 , inport))
                event.connection.send(msg.pack())
        """






class l2_learning (EventMixin):
    """
    Waits for OpenFlow switches to connect and makes them learning switches.
    """
    def __init__ (self, transparent):
        self.listenTo(core.openflow)
        self.transparent = transparent
    """
    When a datapath connects to the controller an event will
     be generated provided you are listening to connection up events.
    """

    def _handle_ConnectionUp (self, event):
        log.debug("Connection %s" % (event.connection,))
        LearningSwitch(event.connection, self.transparent)
        #Firewall(event.connection, self.transparent)



def launch (transparent=False):
    """
    Starts an L2 learning switch.
    """
    core.registerNew(l2_learning, str_to_bool(transparent))

timing = Timer()



#log.debug("installing static flow for policy %s" %s)
# Dpid :the lower 48 bits are Mac address and upper 16 bits are implementer defined.