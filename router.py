from pox.lib.revent import *
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.packet import arp, icmp,pwospf,ipv4
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST, ETHER_ANY
from pox.lib.addresses import IPAddr, IP_ANY, IP_BROADCAST
# from pox.proto.arp_helper import *
import threading
import time
from sets import Set

log = None
if core != None:
    log = core.getLogger()

SWITCH_TYPE_INVALID     = 0x00
SWITCH_TYPE_HUB         = 0x01
SWiTCH_TYPE_ROUTER      = 0x02
ALLSPFRouters = "224.0.0.5"

#TODO: remove this table, and use some file
rtable = {}
rtable["R1"] = [
            ['10.0.0.0/16', '192.0.4.2', 'R1-eth2'],
            ['10.0.3.0/24', '192.0.1.2', 'R1-eth3'],
            ['10.0.1.0/24', '10.0.1.1', 'R1-eth1'],
            ['192.0.0.0/16', '192.0.4.2', 'R1-eth2'],
            ['192.0.1.0/24', '192.0.1.2', 'R1-eth3'],
        ]
rtable["R2"] = [
            ['10.0.0.0/16', '192.0.3.2', 'R2-eth2'],
            ['10.0.1.0/24', '192.0.4.1', 'R2-eth1'],
            ['10.0.2.0/24', '10.0.2.1', 'R2-eth3'],
            ['192.0.0.0/16', '192.0.3.2', 'R2-eth2'],
            ['192.0.4.0/24', '192.0.4.1', 'R2-eth1'],
        ]

rtable["R4"] = [
            ['10.0.0.0/16', '192.0.2.1', 'R4-eth2'],
            ['10.0.2.0/24', '192.0.3.1', 'R4-eth1'],
            ['10.0.4.0/24', '10.0.4.1', 'R4-eth3'],
            ['192.0.0.0/16', '192.0.2.1', 'R4-eth2'],
            ['192.0.3.0/24', '192.0.3.1', 'R4-eth1'],
        ]
rtable["R3"] = [
            ['10.0.0.0/16', '192.0.1.1', 'R3-eth1'],
            ['10.0.4.0/24', '192.0.2.2', 'R3-eth3'],
            ['10.0.3.0/24', '10.0.3.1', 'R3-eth2'],
            ['192.0.0.0/16', '192.0.1.1', 'R3-eth1'],
            ['192.0.2.0/24', '192.0.2.2', 'R3-eth3'],
        ]

OWN_SUBNET = {
    "R1": ['10.0.1.0/24', '10.0.1.1', 'R1-eth1'],
    "R2": ['10.0.2.0/24', '10.0.2.1', 'R2-eth3'],
    "R3": ['10.0.3.0/24', '10.0.3.1', 'R3-eth2'],
    "R4": ['10.0.4.0/24', '10.0.4.1', 'R4-eth3']
}

ROUTERS_IPS = {
            "R1-eth1" : "10.0.1.1",
            "R1-eth2" : "192.0.4.1",
            "R2-eth1" : "192.0.4.2",
            "R2-eth2" : "192.0.3.1",
            "R4-eth1" : "192.0.3.2",
            "R1-eth3" : "192.0.1.1",
            "R3-eth1" : "192.0.1.2",
            "R3-eth2" : "10.0.3.1",
            "R3-eth3" : "192.0.2.1",
            "R4-eth2" : "192.0.2.2",
            "R2-eth3" : "10.0.2.1",
            "R4-eth3" : "10.0.4.1"
        }

# ROUTERS_IP_2_PORT = {}

def getCIDR(subnet_str, netmask_str):
    netmask = netmask_str.split('.')
    binary_str = ''
    for octet in netmask:
        binary_str += bin(int(octet))[2:].zfill(8)
    netmask_cidr = str(len(binary_str.rstrip('0')))
    return subnet_str + '/' + netmask_cidr

class RoutingEntry():
    def __init__(self, txtEntry = []):
        self.netIP          = self.parseTextIp(txtEntry[0])
        self.netMaskCnt     = self.parseTextMaskCnt(txtEntry[0])
        self.netMask        = self.parseTextMask(txtEntry[0])
        self.nextHopIp      = self.parseTextIp(txtEntry[1])
        self.intf           = txtEntry[2]
        self.nextHopIpAddr  = IPAddr(self.textedIP(self.nextHopIp))
        self.netIP         &= self.netMask

    def __str__(self):
        return "netIP: %s/%s, nextHopIp: %s, intf: %s"%(self.textedIP(self.netIP), self.netMaskCnt, self.nextHopIpAddr, self.intf)
    
    def matchTextIp(self, ipText):
        return self.match(self.parseTextIp(ipText))

    def match(self, ip):
        ipp = ip & self.netMask
        return ipp == self.netIP

    def parseTextMaskCnt(self, ip):
        slash = ip.find("/")
        if slash < 0:
            raise Exception("Invalid mask")
        mask = ip[slash + 1 :]
        mask = int(mask)
        if mask < 0 or mask > 32:
            raise Exception("Invalid mask")
        return mask

    def parseTextMask(self, ip):
        mask = self.parseTextMaskCnt(ip)
        intMask = 1
        intMask <<= mask
        intMask -= 1
        intMask <<= (32 - mask)
        return intMask
    
    def parseTextIp(self, ip):
        slash = ip.find("/")
        if slash >= 0:
            ip = ip[:slash]
        ipseg = ip.split(".")
        if len(ipseg) != 4:
            raise Exception("Invalid ip")
        intIP = 0
        for s in ipseg:
            i = int(s)
            if i < 0 or i > 255:
                raise Exception("Invalid ip")
            intIP = intIP << 8
            intIP += i
        return intIP

    def textedIP(self, intIP):
        s = ".".join([ "%s"%((intIP & (255<<(i*8)))>>(i*8)) for i in xrange(3, -1, -1)])
        return s

    def getMatchSize(self):
        return self.netMaskCnt

class RoutingTable():
    def __init__(self):
        self.routingEntries = []
    
    def addEntry(self, entry = []):
        if type(entry) != list:
            raise Exception("Invalid entry")
        if len(entry) != 3:
            raise Exception("Invalid entry: Routing entry must have 3 string fields")
        for st in entry:
            if type(st) != str:
                raise Exception("Invalid entry: Routing entry must have 3 string fields")

        r = RoutingEntry(entry)
        self.routingEntries.append(r)

    def addEntries(self, entries):
        if type(entries) != list:
            raise Exception("Invalide Table")

        for entry in entries:
            self.addEntry(entry)

    def getMatchedEntry(self, ip):
        if ip == None:
            return None
        ip = str(ip)
        matchCnt = -1
        resRoute = None
        for route in self.routingEntries:
            if route.matchTextIp(ip) and matchCnt < route.netMaskCnt:
                matchCnt = route.netMaskCnt
                resRoute = route
        
        return resRoute
    
    def __str__(self):
        return "[" + ", ".join(["<"+str(r)+">" for r in self.routingEntries]) + "]"

class NeighbourEntry():
    def __init__(self):
        self.rid = 0
        self.ip = ""
        self.helloint = 0
        self.uptime = 0
        self.interface = ""
        self.netmask = ""
        self.subnet = ""
        self.own = False

    def __str__(self):
        return "(Rid: "+str(self.rid)+", Ip: "+self.ip + ", helloint: "+str(self.helloint)+", uptime: "+str(self.uptime) + ", netmask: " + self.netmask + ", subnet: " + self.subnet+", interface:"+self.interface+")"

    def expired(self):
        curtime = int(round(time.time()))
        if curtime - self.uptime > 3*self.helloint:
            return True
        return False

def find_subnet(ipaddr_str, netmask_str):
    ipaddr = ipaddr_str.split('.')
    netmask = netmask_str.split('.')
    net_start = [str( int(ipaddr[x]) & int(netmask[x]) ) for x in range(0,4)]
    return '.'.join(net_start)

class NeighbourList():
    def __init__(self):
        self.neighbourList = []

    def __str__(self):
        s = ""
        for ne in self.neighbourList:
            s += str(ne)
        return s

    def checkTimeout(self):
            flag = False
            for ne in self.neighbourList:
                if ne.own==False and ne.expired()==True:
                    print "Deleting ",ne.rid
                    flag = True
            self.neighbourList = [ ne for ne in self.neighbourList if ne.own==True or ne.expired()==False]
            return flag

    def items(self):
        return self.neighbourList

    def getIP(self,rid):
        for ne in self.neighbourList:
            if rid == ne.rid:
                return ne.ip

    def getInterface(self,rid):
        for ne in self.neighbourList:
            if rid == ne.rid:
                return ne.interface

    def addEntry(self,rid,ip,subnet,netmask,interface,helloint,own=False):

        ne = NeighbourEntry()

        ne.rid = rid
        ne.ip = str(IPAddr(ip))
        ne.netmask = str(IPAddr(netmask))
        ne.interface = interface
        ne.subnet = subnet
        ne.helloint = helloint
        ne.uptime = int(round(time.time()))
        ne.own = own

        # If exist in table, update uptime
        for n in self.neighbourList:
            if n.rid == ne.rid and n.ip == ne.ip and n.netmask == ne.netmask:
                n.uptime = int(round(time.time()))
                return 

        # If not exist in table, add to table
        self.neighbourList.append(ne)


class RouterHandler(EventMixin):
    def __init__(self, connection, *ka, **kw):
        self.connection = connection
        self.name = ""
        self.rid = 0
        self.type = SWITCH_TYPE_INVALID
        self.routingInfo = None
        log.debug("Handler: ka:" + str(ka) + " kw: " + str(kw))
        self.listenTo(connection)
        self.intf2ip = {}
        self.port2Mac = {}
        self.intf2Port = {}
        self.port2intf = {}
        self.arpTable = {}
        self.hwadr2Port = {}
        self.outstandingarp = {} #just key:ip and val timestamp(later`)
        self.queuedMsgForArp = {} #nested
        self.ARP_TIMEOUT = 4
        self.myips  = []

        self.helloint = 5
        self.lsuint = 10
        self.adjList = {}

        self.initialize_controller()

        if self.type == SWiTCH_TYPE_ROUTER:
            self.adjList[self.rid] = NeighbourList()
            self.adjList[self.rid].addEntry(0,OWN_SUBNET[self.name][1],
                find_subnet(OWN_SUBNET[self.name][1],"255.255.255.0")
                ,"255.255.255.0",
                OWN_SUBNET[self.name][2],
                self.helloint,True)
            print str(self.adjList[self.rid])

        # LSU Fields
        if self.type == SWiTCH_TYPE_ROUTER:
            self.counter = 0
            update_thread = threading.Thread(target=self.setupUpdateLoop)
            update_thread.daemon = True
            update_thread.start()

    def setupUpdateLoop(self):
        counter = 0
        seq = 0
        while(1):

            if counter%self.helloint == 0:
                self.sendHelloAll()
            if counter%self.lsuint == 0:
                seq += 1
                self.sendLSUAll(seq)

            if self.checkTimeOut():
                seq += 1
                self.sendLSU(seq)

            time.sleep(1)
            counter = counter + 1

    def checkTimeOut(self):
        if self.rid in self.adjList.keys():
            self.adjList[self.rid].checkTimeout()

    def sendHelloAll(self):
        for entry in self.intf_ip:
            self.sendHello(entry)


    def updateRoutingTable(self):
        temp = []

        queue = [(self.rid,[self.rid])]
        visited = Set()
        visited.add(self.rid)
        done = Set()
        while queue:
            (vertex,path) = queue.pop(0)
            if vertex in self.adjList.keys():
                for ne in self.adjList[vertex].items():
                    if ne.rid not in visited:
                        path_new = path + [ne.rid]
                        queue.append((ne.rid, path_new))
                        visited.add(ne.rid)

                        if getCIDR(ne.subnet,ne.netmask) not in done:
                            done.add(getCIDR(ne.subnet,ne.netmask))
                            temp.append([getCIDR(ne.subnet,ne.netmask)
                                ,self.adjList[self.rid].getIP(path_new[1])
                                ,self.adjList[self.rid].getInterface(path_new[1])]) 

        print "**&&*&^%$^%$^"
        if self.name =="R1":
            for key,value in self.adjList.items():
                print key,value
        print self.name,temp
        rtable[self.name] = temp
        self.initialize_controller()

    def sendHello(self,entry):
        inf = entry[0]
        srcip = entry[1]
        port = self.intf2Port[inf]
        mac = self.port2Mac[port]

        pwospf_hello = pwospf()
        pwospf_hello.rid = self.rid
        pwospf_hello.type = pwospf.TYPE_HELLO
        pwospf_hello.helloint = self.helloint << 16
        pwospf_hello.netmask = IPAddr("255.255.255.0").toUnsigned()

        ipp = pkt.ipv4()
        ipp.protocol = ipv4.PWOSPF_PROTOCOL
        ipp.srcip = IPAddr(srcip)
        ipp.dstip = IPAddr(ALLSPFRouters)
        ipp.payload = pwospf_hello

        ether = ethernet()
        ether.type = ethernet.IP_TYPE
        ether.src = mac
        ether.dst = ETHER_BROADCAST
        ether.payload = ipp

        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = ether.pack()
        self.connection.send(msg)

    def sendLSUAll(self,seq):
        if len(self.adjList[self.rid].items())==0:
            return
        for ne in self.adjList[self.rid].items():
            self.sendLSU(seq , ROUTERS_IPS[ne.interface] , ne.ip)

    def sendLSU(self,seq,srcip,dstip):
        print "Sending LSU Packets: ",self.name
        pwospf_hello = pwospf()
        pwospf_hello.rid = self.rid
        pwospf_hello.type = pwospf.TYPE_LSU
        pwospf_hello.seq = seq
        pwospf_hello.nadv = len(self.adjList[self.rid].items())

        for ne in self.adjList[self.rid].items():
            print ne.subnet
            pwospf_hello.advList.append(IPAddr(ne.subnet).toUnsigned())
            pwospf_hello.advList.append(IPAddr(ne.netmask).toUnsigned())
            pwospf_hello.advList.append(ne.rid)

        ipp = pkt.ipv4()
        ipp.protocol = ipv4.PWOSPF_PROTOCOL
        ipp.srcip = IPAddr(srcip)
        ipp.dstip = IPAddr(dstip)
        ipp.payload = pwospf_hello

        ether = ethernet()
        ether.type = ethernet.IP_TYPE
        ether.payload = ipp

        self.send_ipv4_packet(ether)
    
    def initialize_controller(self):
        for port in self.connection.features.ports:
            if self.name == "":
                self.name = port.name[:2]
            if port.name.find("-") >= 0:
                self.port2Mac[port.port_no] = port.hw_addr
                self.intf2Port[port.name] = port.port_no
                self.port2intf[port.port_no] = port.name
                if port.name in ROUTERS_IPS:
#                     ROUTERS_IP_2_PORT[ROUTERS_IPS[port.name]] = port.hw_addr
                    self.myips.append(ROUTERS_IPS[port.name])
            # log.debug(port.name + str(port.__dict__))
        
        if self.name[0] == "S":
            self.type = SWITCH_TYPE_HUB
        elif self.name[0] == "R":
            self.type = SWiTCH_TYPE_ROUTER
            self.intf_ip = [ [key,value] for key,value in ROUTERS_IPS.items() if self.name==key[0:2] ]
            self.rid = IPAddr(self.intf_ip[0][1]).toUnsigned()

        if self.name in rtable:
            self.routingInfo = RoutingTable()
            self.routingInfo.addEntries(rtable[self.name])

    def _handle_PacketIn (self, event):
        #log.debug("Packet In event in router %s"%self.name)
        packet = event.parsed # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

#         packet_in = event.ofp # The actual ofp_packet_in message.
        
        if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
            self.drop_packet(event)
            return

        if self.type == SWITCH_TYPE_HUB:
            self.act_like_hub(event, packet)
#             self.act_like_l2switch(event, packet)
            
        elif self.type == SWiTCH_TYPE_ROUTER:
            self.act_like_router(event, packet)
            #log.debug("%s: Just implemented"%self.name)
        else:
            log.warning("Unhandled switch type")

    def drop_packet(self, event, duration = None):
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
        elif event.ofp.buffer_id is not None:
            msg = of.ofp_packet_out()
            msg.buffer_id = event.ofp.buffer_id
            msg.in_port = event.port
            self.connection.send(msg)

    def act_like_hub(self, event, packet):
        packet_in = event.ofp
        match = of.ofp_match.from_packet(packet)
        msg = of.ofp_flow_mod()
        msg = of.ofp_packet_out()
        msg.data = packet_in
        
        #log.debug("match info at %s: %s"%(self.name, match))

        # Add an action to send to the specified port
        action = of.ofp_action_output(port = of.OFPP_ALL)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)
    
    def act_like_l2switch(self, event, packet):
        dst_port = None
        self.hwadr2Port[packet.src] = event.port
        if packet.dst not in (ETHER_ANY, ETHER_BROADCAST) and not packet.dst.is_multicast:
            dst_port = self.hwadr2Port.get(packet.dst, None)
        if dst_port is None:
            packet_in = event.ofp
            match = of.ofp_match.from_packet(packet)
            msg = of.ofp_flow_mod()
            msg = of.ofp_packet_out()
            msg.data = packet_in
            
            #log.debug("match info at %s: %s"%(self.name, match))
    
            # Add an action to send to the specified port
            action = of.ofp_action_output(port = of.OFPP_ALL)
            msg.actions.append(action)
    
            # Send message to switch
            self.connection.send(msg)
        else:
                msg = of.ofp_flow_mod()
                msg.match.dl_dst = packet.src
                msg.match.dl_src = packet.dst
                msg.actions.append(of.ofp_action_output(port = event.port))
                event.connection.send(msg)
            
                # This is the packet that just came in -- we want to
                # install the rule and also resend the packet.
                msg = of.ofp_flow_mod()
                msg.data = event.ofp # Forward the incoming packet
                msg.match.dl_src = packet.src
                msg.match.dl_dst = packet.dst
                msg.actions.append(of.ofp_action_output(port = dst_port))
                event.connection.send(msg)

           
    def act_like_router(self, event, packet):
        if packet.find("arp"):
            self.handle_arp_packet(event, packet)
        elif packet.find("ipv4"):
            self.handle_ipv4_packet(event, packet)
        else:
            self.drop_packet(event)

    def handle_ipv4_packet(self, event, packet):
        if packet.find('pwospf'):
            self.handle_pwospf_packet(event,packet)
            return

        match = of.ofp_match.from_packet(packet)
        rd = self.routingInfo.getMatchedEntry(match.nw_dst)
        rs = self.routingInfo.getMatchedEntry(match.nw_src)
        if match.nw_dst in self.myips:
            log.debug("%s: rs: %s, rs: %s"%(self.name, rs, rd))
            if packet.find("icmp") and packet.find("icmp").type == pkt.TYPE_ECHO_REQUEST:
                    self.send_icmp_msg_small(packet, match, event)
        else:
            log.debug("%s: its a ip pkt match: %s"%(self.name, match))
            if rd is not None:
                    self.forward_pkt_to_next_hop(packet, match, event, rd)
            else:
                self.send_icmp_msg_small(packet, match, event, pkt.TYPE_DEST_UNREACH, packet)
                #self.drop_packet(event)

    def send_ipv4_packet(self,packet,event=None):
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.data = packet.pack()
        if event is not None:
            msg.in_port = event.port
        self.connection.send(msg)

    def forwardLSUPacket(self,packet,event):
        pwospf = packet.find('pwospf')
        pwospf.ttl-=1

        if pwospf.ttl == 0:
            return
        for ne in self.adjList[self.rid].items():
            ipv4 = packet.find('ipv4')
            ipv4.dstip = IPAddr(ne.ip)
            self.send_ipv4_packet(packet,event)

    def handle_pwospf_packet(self, event, packet):
        ipv4 = packet.find('ipv4')
        pwospf = packet.find('pwospf')

        if pwospf.type == pkt.pwospf.TYPE_HELLO:

            print "HELLO received", str(pwospf),self.port2intf[event.port]
            
            intf = self.port2intf[event.port]

            if self.rid not in self.adjList.keys():
                self.adjList[self.rid] = NeighbourList()

            self.adjList[self.rid].addEntry(pwospf.rid,str(ipv4.srcip),find_subnet(str(ipv4.srcip),str(IPAddr(pwospf.netmask)))
                ,str(IPAddr(pwospf.netmask)),intf,pwospf.helloint)

        if pwospf.type == pkt.pwospf.TYPE_LSU:
            if pwospf.rid == self.rid:
                return
            print "LSU received", str(pwospf)

            ip = str(packet.find('ipv4').srcip)

            self.adjList[pwospf.rid] = NeighbourList()

            advList = pwospf.matrix(pwospf.advList,3)

            # print self.name,pwospf.rid,advList
            for adv in advList:
                subnet = adv[0]
                netmask = adv[1]
                rid = adv[2]
                self.adjList[pwospf.rid].addEntry(rid,str(IPAddr(ip)),str(IPAddr(subnet)),str(IPAddr(netmask)),"R0-eth0",0)
            
            self.forwardLSUPacket(packet,event)

            self.updateRoutingTable()

    def forward_pkt_to_next_hop(self, packet, match, event, route, justSend = False):
        ipp = packet.find("ipv4")
        if ipp.ttl <= 1:
            return self.send_icmp_ttl_exceed(packet, match, event)
    
        nextHopIp = route.nextHopIpAddr if str(route.nextHopIpAddr) not in self.myips else match.nw_dst
        if not justSend and nextHopIp not in self.arpTable:
            self.send_arp_request(event, route, packet, match, nextHopIp)
            q = self.queuedMsgForArp.get(nextHopIp, [])
            q.append([packet, match, event, route])
            self.queuedMsgForArp[nextHopIp] = q
            return
        
        if nextHopIp not in self.arpTable:
            log.info("%s: mac for nexthopip(%s) is not present in arptable(%s). returning"%(self.name, nextHopIp, self.arpTable))
        
        nextHopAddr = self.arpTable[nextHopIp]

        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        #import pdb; pdb.set_trace()
        log.debug("%s: intf: %s, ,port2Mac: %s, intf2Port: %s, dst: %s", self.name, route.intf, self.port2Mac, self.intf2Port, nextHopAddr)

        #msg.actions.append(action)
        action = of.ofp_action_dl_addr()
        msg.actions.append(action.set_dst(nextHopAddr))
        msg.actions.append(action.set_src(self.port2Mac[self.intf2Port[route.intf]]))
        msg.actions.append(of.ofp_action_output(port = self.intf2Port[route.intf]))
        msg.data = event.ofp
        event.connection.send(msg)


    def send_icmp_msg_large(self, event, src_ip = IP_ANY, dst_ip = IP_ANY, src_mac = ETHER_BROADCAST,
                            dst_mac = ETHER_BROADCAST, payload = None, icmp_type = pkt.TYPE_ECHO_REPLY):
        
        icmp = pkt.icmp()
        icmp.type = icmp_type
        icmp.payload = payload

        # Make the IP packet around it
        ipp = pkt.ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = src_ip
        ipp.dstip = dst_ip

        e = pkt.ethernet()
        e.src = src_mac
        e.dst = dst_mac
        e.type = e.IP_TYPE

        ipp.payload = icmp
        e.payload = ipp

        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.data = e.pack()
        msg.in_port = event.port
        event.connection.send(msg)
    
    def send_icmp_ttl_exceed(self, packet, match, event):
        payload = b"    "+packet.find("ipv4").pack()
        return self.send_icmp_msg_large(event, IPAddr(ROUTERS_IPS[self.port2intf[event.port]]), packet.find("ipv4").srcip, packet.dst, packet.src, payload, pkt.TYPE_TIME_EXCEED)

    def send_icmp_msg_small(self, packet, match, event, icmp_type = pkt.TYPE_ECHO_REPLY, payload = None):
        pload = payload if payload is not None or packet is None or packet.find("icmp") is None else packet.find("icmp").payload
        return self.send_icmp_msg_large(event, packet.find("ipv4").dstip, packet.find("ipv4").srcip, packet.dst, packet.src, pload, icmp_type)
        
        icmp = pkt.icmp()
        icmp.type = pkt.TYPE_ECHO_REPLY
        icmp.payload = packet.find("icmp").payload

        # Make the IP packet around it
        ipp = pkt.ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = packet.find("ipv4").dstip
        ipp.dstip = packet.find("ipv4").srcip

        e = pkt.ethernet()
        e.src = packet.dst
        e.dst = packet.src
        e.type = e.IP_TYPE

        ipp.payload = icmp
        e.payload = ipp

        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.data = e.pack()
        msg.in_port = event.port
        event.connection.send(msg)

        log.debug("%s pinged %s", ipp.dstip, ipp.srcip)

#================================
#    All arp business goes below
#================================
    def handle_arp_packet(self, event, packet):
        match = of.ofp_match.from_packet(packet)
        if match.nw_src not in self.arpTable and match.nw_src not in (IP_ANY, IP_BROADCAST) and match.dl_src not in (ETHER_ANY, ETHER_BROADCAST):
            self.arpTable[match.nw_src] = match.dl_src
        if match.nw_dst not in self.arpTable and match.nw_dst not in (IP_ANY, IP_BROADCAST) and match.dl_dst not in (ETHER_ANY, ETHER_BROADCAST):
            self.arpTable[match.nw_dst] = match.dl_dst
            
        if match.nw_proto == pkt.arp.REQUEST:
            log.debug("%s: got rerequest, match: %s"%(self.name, match))
            if match.nw_dst == IPAddr(ROUTERS_IPS[self.port2intf[event.port]]):
                self.send_arp_response(packet, match, event)
            else:
                log.debug("%s: got rerequest and droping it, match: %s"%(self.name, match))
                self.drop_packet(event)
        elif match.nw_proto == pkt.arp.REPLY:
#             import pdb; pdb.set_trace()
            log.debug("%s: got arp response, match: %s"%(self.name, match))
            if match.nw_src in self.outstandingarp:
                for waiting in self.queuedMsgForArp.get(match.nw_src, []):
                    #packetN, matchN, event, route = waiting
                    self.forward_pkt_to_next_hop(*waiting)
                try:
                    del self.queuedMsgForArp[match.nw_src]
                    del self.outstandingarp[match.nw_src]
                except Exception, e:
                    log.info("%s: problem"%self.name)
            else:
                self.drop_packet(event)  

    def send_arp_response(self, packet, match, event):
        # reply to ARP request
        #import pdb; pdb.set_trace()
        r = arp()
        r.opcode = arp.REPLY
        r.hwdst = match.dl_src
        r.protosrc = match.nw_dst
        r.protodst = match.nw_src
        r.hwsrc = self.port2Mac[event.port]
        self.arpTable[match.nw_src] = match.dl_src
        e = ethernet(type=packet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
        e.set_payload(r)
        log.debug("%s:%i %i answering ARP for %s" % (self.name, event.dpid, event.port, str(r.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = event.port
        event.connection.send(msg)
        
    def send_arp_request(self, event, route, packet, match, nextHopIp):
        
        if nextHopIp in self.outstandingarp and time.time() > self.outstandingarp[nextHopIp] + self.ARP_TIMEOUT:
            return
        self.outstandingarp[nextHopIp] = time.time()
        r = pkt.arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        
        r.protodst = nextHopIp
        r.hwsrc = self.port2Mac[self.intf2Port[route.intf]]
        r.protosrc = IPAddr(ROUTERS_IPS[route.intf])
        
        #r.protodst = packet.next.dstip
        e = ethernet(type=ethernet.ARP_TYPE, src=r.hwsrc,
                     dst=r.hwdst)
        e.set_payload(r)
        log.debug("%s ARPing for %s on behalf of %s" % (route.intf, r.protodst, r.protosrc))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.actions.append(of.ofp_action_output(port = self.intf2Port[route.intf]))
        msg.in_port = event.port
        event.connection.send(msg)
    
    def send_arp_response(self, packet, match, event):
        # reply to ARP request
        #import pdb; pdb.set_trace()
        r = arp()
        r.opcode = arp.REPLY
        r.hwdst = match.dl_src
        r.protosrc = match.nw_dst
        r.protodst = match.nw_src
        r.hwsrc = self.port2Mac[event.port]
        self.arpTable[match.nw_src] = match.dl_src
        e = ethernet(type=packet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
        e.set_payload(r)
        log.debug("%s:%i %i answering ARP for %s" % (self.name, event.dpid, event.port, str(r.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = event.port
        event.connection.send(msg)

    
#     def _handle_QueueStatsReceived(self, e): 
#         log.info("inside QueueStatsReceived") 
#     def _handle_ConnectionDown(self, e): 
#         log.info("inside ConnectionDown") 
#     def _handle_PortStatus(self, e): 
#         log.info("inside PortStatus") 
#     def _handle_PortStatsReceived(self, e): 
#         log.info("inside PortStatsReceived") 
#     def _handle_RawStatsReply(self, e): 
#         log.info("inside RawStatsReply") 
#     def _handle_AggregateFlowStatsReceived(self, e): 
#         log.info("inside AggregateFlowStatsReceived") 
#     def _handle_ConnectionUp(self, e): 
#         log.info("inside ConnectionUp") 
#     def _handle_SwitchDescReceived(self, e): 
#         log.info("inside SwitchDescReceived") 
#     def _handle_FlowStatsReceived(self, e): 
#         log.info("inside FlowStatsReceived") 
#     def _handle_TableStatsReceived(self, e): 
#         log.info("inside TableStatsReceived") 
#     def _handle_ErrorIn(self, e): 
#         log.info("inside ErrorIn") 
#     def _handle_BarrierIn(self, e): 
#         log.info("inside BarrierIn") 
#     def _handle_FlowRemoved(self, e): 
#         log.info("inside FlowRemoved") 
#     def _handle_(self, e): 
#         log.info("inside ") 

class DefHalndler(EventMixin):
    """
    Waits for OpenFlow switches to connect and makes them learning switches.
    """
    def __init__ (self, transparent):
        EventMixin.__init__(self)
        self.listenTo(core.openflow)
        self.transparent = transparent

    def _handle_ConnectionUp (self, event):
        log.debug("Connection %s" % (event.connection,))
        RouterHandler(event.connection, transparent=self.transparent)
    #def _handle_PacketIn(self, event):
    #    log.debug("Packet In event in router %s"%self.name)


def launch (transparent=False):
    """
    Starts an Simple Router Topology
    """        
    core.registerNew(DefHalndler, str_to_bool(transparent))
    
    #r = get_ip_setting()
    #if r == -1:
    #    log.debug("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)
    #    sys.exit(2)
    #else:
    #    log.debug('*** ofhandler: Successfully loaded ip settings for hosts\n %s\n' % IP_SETTING)
