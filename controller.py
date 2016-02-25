from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp
from pox.lib.packet.ethernet import ethernet,ETHER_BROADCAST
from pox.lib.addresses import IPAddr,EthAddr
import struct,socket
import pox.lib.packet as pkt
import sys

log = core.getLogger()

switch_list = {"00-00-00-00-00-01","00-00-00-00-00-02"}

class FloodSwitch (object):
	def __init__ (self, connection):
	    self.connection = connection
	    connection.addListeners(self)

	def _handle_PacketIn (self, event):
		packet = event.parsed

		if packet.type == packet.IP_TYPE:
			print "Flooding ICMP from ", packet.src, packet.payload
		elif packet.type == packet.ARP_TYPE:
			if packet.payload.opcode == arp.REPLY:
				print "Flooding ARP REPLY from ", packet.payload.hwsrc
			else:
				print "Flooding ARP REQ from ", packet.payload.hwsrc

		def flood(message = None):
			print "Flooding by ",event.dpid
			msg = of.ofp_packet_out()
			msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
			msg.data = event.ofp
			msg.in_port = event.port
			self.connection.send(msg)
		flood(packet)

class ForwardTable():
	def __init__ (self, dpid):
		self.cache = {}
		with open("/home/mininet/IAP/static_routing/"+dpid_to_str(dpid)[-1:]) as table:
			self.rtable = []
			for line in table.readlines():
				field =line.split(',')
				self.rtable.append([field[0],field[1],field[2],field[3]])

	def iptoint(self,ip):
		return int(socket.inet_aton(ip).encode('hex'),16)

	def findNextHop(self,dstip,event):
		# diff=10
		# nexthop = ''
		# for row in self.rtable:
		# 	d = (self.iptoint(row[1]) & self.iptoint(str(dstip))) - self.iptoint(row[0])
		# 	#print "findHop",d,row[0],str(dstip),event.dpid
		# 	if d<0:
		# 		d = -d
		# 	if d<diff:
		# 		#print "Found ", row[2], event.dpid
		# 		diff = d
		# 		nexthop = row[2]
		# 	# if self.iptoint(row[1]) & self.iptoint(str(dstip))== self.iptoint(row[0]):
		# return nexthop
		if str(dstip) in self.cache:
			return self.cache[str(dstip)]
		min_diff = int('0xFFFFFFFF',0)
		for row in self.rtable:
			diff = (self.iptoint(row[1]) & self.iptoint(str(dstip))) - self.iptoint(row[0])
			#print "diff,dstip,dsttab,netmask",diff, str(dstip), row[0],row[1]
			if min_diff > diff:
				min_diff = diff
			if diff == 0:
				self.cache[str(dstip)] = row[2]
				return row[2]
		
		if min_diff > int('0xFF',0):
			return -1
		else:
			return -2
		return None

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
			print "Received ARP Request (for, from, at) ",packet.payload.protodst, packet.payload.protosrc, event.dpid

			if str(packet.payload.protosrc)[-1:]=='1':
				if self.ip != packet.payload.protodst:
					return
			# hop = self.forwardTable.findNextHop(packet.payload.protodst,event)
			# if hop is None:
			# 	return
			# if str(packet.payload.protosrc)==hop:
			# 	return

			# print "I am next hop (me,next hop from me)",self.ip,hop
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

			self.ipToPort[str(packet.payload.protosrc)] = event.port
			self.ipToMac[str(packet.payload.protosrc)] = packet.payload.hwsrc

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
			print "Received ARP REPLY from (dest router) :",packet.payload.protosrc
			arp_reply = packet.payload

			self.ipToPort[str(arp_reply.protosrc)] = event.port
			self.ipToMac[str(arp_reply.protosrc)] = arp_reply.hwsrc
			print "Saving Mapping for (mappedIp, mappedPort, at ) :", arp_reply.protosrc, event.port, event.dpid
			print self.ipToPort
			print "Resending buffered packets ... at Router",event.dpid
			# print self.packetQueue[str(arp_reply.protosrc)]
			if str(arp_reply.protosrc) not in self.packetQueue.keys():
				return
			for pac in self.packetQueue[str(arp_reply.protosrc)]:
				print "Packet - ",str(pac.find('icmp')),arp_reply.hwsrc
				msg = of.ofp_packet_out()
				msg.actions.append(of.ofp_action_output(port = event.port))
				pac.src = self.mac
				pac.dst = arp_reply.hwsrc
				msg.data = pac.pack()
				# msg.in_port = event.port
				event.connection.send(msg)

			self.packetQueue[str(arp_reply.protosrc)] = []

		else:
			print "Some other ARP opcode, probably do something smart here"

	def do_arp(self,dstip):

		print "Doing ARP REQUEST for (ip, source router) :",dstip, self.connection.dpid
		arp_req = arp()
		arp_req.hwsrc = self.mac
		arp_req.opcode = arp.REQUEST
		arp_req.protosrc = self.ip
		print "This is the string : ", dstip
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

	def handle_icmp(self,event):
		print "Replying to Ping: ",event.dpid
		packet = event.parsed
		icmp_reply = icmp()
		icmp_reply.type = pkt.TYPE_ECHO_REPLY
		icmp_reply.payload = packet.find("icmp").payload

		# Make the IP packet around it
		ipp = pkt.ipv4()
		ipp.protocol = ipp.ICMP_PROTOCOL
		ipp.srcip = packet.find("ipv4").dstip
		ipp.dstip = packet.find("ipv4").srcip

		# Ethernet around that...
		e = pkt.ethernet()
		e.src = packet.dst
		e.dst = packet.src
		e.type = e.IP_TYPE

		# Hook them up...
		ipp.payload = icmp_reply
		e.payload = ipp

		# Send it back to the input port
		msg = of.ofp_packet_out()
		msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
		msg.data = e.pack()
		msg.in_port = event.port
		event.connection.send(msg)

	def reply_icmp_error(self, event, icmp_type, code):
		print "Replying Host Unreachable from ", event.dpid
		packet = event.parsed
		icmp_reply = icmp()
		icmp_reply.type = icmp_type
		icmp_reply.code = code
		# icmp_reply.payload = packet.find("icmp").payload
		d = packet.next.pack()
		d = d[:packet.next.hl*4+8]
		d = struct.pack("!HH", 0, 0) + d
		icmp_reply.payload = d

		# Make the IP packet around it
		ipp = pkt.ipv4()
		ipp.protocol = ipp.ICMP_PROTOCOL
		ipp.srcip = self.ip
		ipp.dstip = packet.find("ipv4").srcip

		# Ethernet around that...
		e = pkt.ethernet()
		e.src = self.mac
		e.dst = packet.src
		e.type = e.IP_TYPE

		# Hook them up...
		ipp.payload = icmp_reply
		e.payload = ipp

		# Send it back to the input port
		msg = of.ofp_packet_out()
		msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
		msg.data = e.pack()
		msg.in_port = event.port
		print "Sending to (fromIP, toIP, fromMAC, toMAC) : ", ipp.srcip, ipp.dstip, e.src, e.dst
		event.connection.send(msg)

	def handle_packet(self,event):
		packet = event.parsed

		ipv4 = packet.find('ipv4')
		if ipv4.csum!=ipv4.checksum():
			print "Checksum error!!"

		print 'TTL ', ( ipv4.ttl, event.dpid)

		if ipv4.ttl == 0:
			print 'TTL EXPIRED', event.dpid
			self.reply_icmp_error(event, pkt.TYPE_TIME_EXCEED, pkt.CODE_UNREACH_NET)
			return

		if ipv4.dstip==self.ip:
			self.handle_icmp(event)
			return

		ipv4.ttl = ipv4.ttl - 1
		ipv4.csum = ipv4.checksum()

		hop = self.forwardTable.findNextHop(ipv4.dstip,event)
		print "Normal Packet received at (routerID, selfIP, nextHop) :", event.dpid, self.ip, hop

		if hop == -1:
			self.reply_icmp_error(event, pkt.TYPE_DEST_UNREACH, pkt.CODE_UNREACH_NET);
		elif hop == -2:
			self.reply_icmp_error(event, pkt.TYPE_DEST_UNREACH, pkt.CODE_UNREACH_HOST);

		if hop not in self.ipToPort:

			if hop not in self.packetQueue:
				self.packetQueue[hop] = []

			print "Queuing packet (at, seq) :",event.dpid, str(packet.find('icmp'))
			self.packetQueue[hop].append(packet)
			self.do_arp(hop)
		else:
			print "Sending message",event.dpid,hop
			msg = of.ofp_packet_out()
			port = self.ipToPort[hop]
			macdst = self.ipToMac[hop]

			msg.actions.append(of.ofp_action_output(port = port))
			packet.src = self.mac
			packet.dst = macdst
			msg.data = packet.pack()
			msg.in_port = event.port
			self.connection.send(msg)

	def _handle_PacketIn (self, event):
		print "Got packet at ", event.dpid
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
