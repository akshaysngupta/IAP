from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet,ETHER_BROADCAST
from pox.lib.addresses import IPAddr,EthAddr
import struct,socket
import pox.lib.packet as pkt

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
		return int(socket.inet_aton(ip).encode('hex'),16)

	def findNextHop(self,dstip,event):
		diff=10
		nexthop = ''
		for row in self.rtable:
			d = (self.iptoint(row[1]) & self.iptoint(str(dstip))) - self.iptoint(row[0])
			#print "findHop",d,row[0],str(dstip),event.dpid
			if d<0:
				d = -d
			if d<diff:
				#print "Found ", row[2], event.dpid
				diff = d
				nexthop = row[2]
			# if self.iptoint(row[1]) & self.iptoint(str(dstip))== self.iptoint(row[0]):
		return nexthop

class StaticRouter (object):
	def __init__ (self, connection):
		self.connection = connection
		connection.addListeners(self)
		self.forwardTable = ForwardTable(self.connection.dpid)

		self.ipToPort = {}
		self.ipToMac = {}
		self.packetQueue = {}
		self.mac = EthAddr("00:12:34:56:78:9" + dpid_to_str(self.connection.dpid)[-1:])
		self.ip = IPAddr("10.0."+ str(int(dpid_to_str(self.connection.dpid)[-1:])-2) +".1")
		print "Router Details:",self.connection.dpid,self.mac,self.ip

	def handle_arp(self,event):
		packet = event.parsed
		if packet.payload.opcode == arp.REQUEST:
			print "REQRecieved ARP Request for ",packet.payload.protodst, event.dpid

			if str(packet.payload.protosrc)[-1:]=='1':
				if self.ip != packet.payload.protodst:
					return
			# print "REQCurrent Table", self.ipToPort
			# hop = self.forwardTable.findNextHop(packet.payload.protodst,event)
			# if hop == '':
			# 	print "Found Nothing Router",event.dpid
			# 	return

			# print "REQFound Next Hop ", hop
			# print "REQCreating Reply"
			arp_reply = arp()
			arp_reply.hwsrc = self.mac
			arp_reply.hwdst = packet.src
			arp_reply.opcode = arp.REPLY
			arp_reply.protosrc = packet.payload.protodst
			arp_reply.protodst = packet.payload.protosrc

			ether = ethernet()
			ether.type = ethernet.ARP_TYPE
			ether.dst = packet.src
			ether.src = self.mac
			ether.payload = arp_reply

			msg = of.ofp_packet_out()
			msg.data = ether.pack()
			msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
			msg.in_port = event.port
			event.connection.send(msg)

		elif packet.payload.opcode == arp.REPLY:
			print "REPRecieved ARP REPLY"
			arp_reply = packet.payload

			print "REPSaving Mapping ", arp_reply.protosrc, event.port
			self.ipToPort[str(arp_reply.protosrc)] = event.port
			self.ipToMac[str(arp_reply.protosrc)] = arp_reply.hwsrc
			print self.ipToPort

			for pac in self.packetQueue[str(arp_reply.protosrc)]:
				msg = of.ofp_packet_out()
				msg.actions.append(of.ofp_action_output(port = event.port))
				pac.dst = self.ipToMac[str(arp_reply.protosrc)]
				msg.data = pac.pack()
				msg.in_port = event.port
				self.connection.send(msg)
			self.packetQueue[str(arp_reply.protosrc)] = []

		else:
			print "Some other ARP opcode, probably do something smart here"

	def do_arp(self,dstip):

		print "Doing ARP REQUEST for ",dstip, self.connection.dpid
		arp_req = arp()
		arp_req.hwsrc = self.mac
		arp_req.opcode = arp.REQUEST
		arp_req.protosrc = self.ip
		arp_req.protodst = IPAddr(dstip)

		ether = ethernet()
		ether.type = ethernet.ARP_TYPE
		ether.src = self.mac
		ether.dst = ETHER_BROADCAST
		ether.payload = arp_req

		msg = of.ofp_packet_out()
		msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
		msg.data = ether.pack()
		msg.in_port = self.event.port
		self.connection.send(msg)

	def handle_packet(self,event):

		packet = event.parsed

		ipv4 = packet.payload

		hop = self.forwardTable.findNextHop(ipv4.dstip,event)
		print "Processing packet",event.dpid,hop

		if hop not in self.ipToPort:

			if hop not in self.packetQueue:
				self.packetQueue[hop] = []

			self.packetQueue[hop].append(packet)
			self.do_arp(hop)
		else:
			print "Sending message",event.dpid,hop
			msg = of.ofp_packet_out()
			port = self.ipToPort[hop]
			macdst = self.ipToMac[hop]

			msg.actions.append(of.ofp_action_output(port = port))
			packet.dst = macdst
			msg.data = packet.pack()
			msg.in_port = event.port
			self.connection.send(msg)

	def _handle_PacketIn (self, event):
		self.event = event
		packet = event.parsed

		if packet.type == packet.ARP_TYPE:
			self.handle_arp(event)
		if packet.type == packet.IP_TYPE:
			self.handle_packet(event)


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
