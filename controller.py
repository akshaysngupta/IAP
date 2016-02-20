from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr,EthAddr
import struct,socket

log = core.getLogger()

switch_list = {"00-00-00-00-00-01","00-00-00-00-00-02"}

class FloodSwitch (object):
	def __init__ (self, connection):
	    self.connection = connection
	    connection.addListeners(self)

	def _handle_PacketIn (self, event):
		packet = event.parsed

		def flood(message = None):
			log.debug("Switch %s %s"% (dpid_to_str(event.dpid),event.dpid))
			log.debug("Flooding!!")
			msg = of.ofp_packet_out()
			msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
			msg.data = event.ofp
			msg.in_port = event.port
			self.connection.send(msg)

		flood(packet)

class ForwardTable():
	def __init__ (self, dpid):
		with open("/home/mininet/IAP/static_routing/"+dpid_to_str(dpid)[-1:]) as table:
			self.rtable = []
			for line in table.readlines():
				field =line.split(',')
				self.rtable.append([field[0],field[1],field[2],field[3]])

	def iptoint(self,ip):
		log.debug("IP from file: %s" % (ip,))
		packedIP = socket.inet_aton(ip)
		return  struct.unpack("!L",packedIP) 

	def findNextHop(self,dstip):
		for row in self.rtable:
			log.level(row[0])
			log.level(IPAddr(row[0]))
			if EthAddr(IPAddr(row[1])) and dstip == EthAddr(IPAddr(row[0])):
				return row

class StaticRouter (object):
	def __init__ (self, connection):
		self.connection = connection
		connection.addListeners(self)
		self.forwardTable = ForwardTable(self.connection.dpid)

	def _handle_PacketIn (self, event):
		packet = event.parsed

		hop = self.forwardTable.findNextHop(packet.dst)
		log.debug("Forwarding at port %s" % (hop[2],))

		msg = of.ofp_flow_mod()
		msg.match = of.ofp_match.from_packet(packet, event.port)
		msg.idle_timeout = 10
		msg.hard_timeout = 30
		msg.actions.append(of.ofp_action_output(port = port))
		msg.data = event.ofp # 6a
		self.connection.send(msg)


class Register(object):
  def __init__ (self):
    core.openflow.addListeners(self)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))

    if dpid_to_str(event.connection.dpid) in switch_list:
      FloodSwitch(event.connection)
    else:
      StaticRouter(event.connection)


def launch():
  core.registerNew(Register)
