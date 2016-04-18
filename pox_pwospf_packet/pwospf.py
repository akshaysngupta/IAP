# Copyright 2011 James McCauley
# Copyright 2008 (C) Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file is derived from the packet library in NOX, which was
# developed by Nicira, Inc.

#======================================================================
#
#                          IPv4 Header Format
#
# #   0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |   Version #   |     Type      |         Packet length         |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                          Router ID                            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                           Area ID                             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           Checksum            |             Autype            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                       Authentication                          |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                       Authentication                          |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# LSU Packet
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Sequence                |          TTL                    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                      # advertisements                         |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                                                               |
#    +-                                                            +-+
#    |                  Link state advertisements                    |
#    +-                                                            +-+
#    |                              ...                              |
#
# Hello Packet
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                        Network Mask                           |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |         HelloInt              |           padding             |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Advertisements
 # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 #   |                           Subnet                              |
 #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 #   |                           Mask                                |
 #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 #   |                         Router ID                             |
 #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# #
#======================================================================

import struct
import time
from packet_utils       import *
from tcp import *
from udp import *
from icmp import *
from igmp import *

from packet_base import packet_base

from pox.lib.addresses import IPAddr, IP_ANY, IP_BROADCAST

class pwospf(packet_base):
    "PWOSPF packet struct"

    Pv2 = 2
    MIN_LEN = 24
    TYPE_HELLO = 1
    TYPE_LSU = 4

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)
        self.prev = prev

        self.version = 2
        self.type = 0
        self.plen = pwospf.MIN_LEN
        self.rid = 0
        self.aid = 0
        self.csum = 0
        self.autype = 0
        self.auth = 0

        # Hello packet
        self.helloint = 0
        self.netmask = 0

        # LSU packet
        self.seq = 0
        self.ttl = 64
        self.nadv = 0
        self.advList = []

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        if self.type==pwospf.TYPE_HELLO:
            s = "[PWOSPF Hello: (Router: "+ str(self.rid) +", Type: "+str(self.type) + ", Length: " + str(self.plen) + ", Helloint:" +str(self.helloint)+")]"
        if self.type==pwospf.TYPE_LSU:
            s = "[PWOSPF LSU: (Router: "+ str(self.rid) +", Type: "+str(self.type) + ", Length: " + str(self.plen)+")]"

        return s

    def matrix(self,l,n):
        return [l[i:i+n] for i in xrange(0,len(l),n)]

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        dlen = len(raw)
        if dlen < pwospf.MIN_LEN:
            self.msg('warning IP packet data too short to parse header: data len %u' % (dlen,))
            return

        (self.version, self.type, self.plen, self.rid, self.aid, self.csum,
            self.autype, self.auth) \
             = struct.unpack('!BBHIIHHQ', raw[:pwospf.MIN_LEN])

        if self.version != pwospf.Pv2:
            self.msg('(ip parse) warning IP version %u not IPv4' % self.v)
            return
        elif self.plen < pwospf.MIN_LEN:
            self.msg('(pwospf parse) warning invalid PWOSPF len %u' % self.plen)
            return

        if self.type==pwospf.TYPE_HELLO:
           (self.netmask,self.helloint) = struct.unpack('!II', raw[pwospf.MIN_LEN:self.plen])
           self.helloint = self.helloint >> 16
           self.next =  raw[self.MIN_LEN + 8 :self.plen]

        if self.type==pwospf.TYPE_LSU:
            (self.seq,self.ttl,self.nadv) = struct.unpack('!HHI', raw[pwospf.MIN_LEN:pwospf.MIN_LEN+8])
            nadv_string = '!'+str(3 * self.nadv) + "I"
            self.advList =  struct.unpack(nadv_string, raw[pwospf.MIN_LEN+8:self.plen])
            self.next =  raw[self.MIN_LEN + 8 + self.nadv * 12 : self.plen]

        self.parsed = True

    def checksum(self):
        data = struct.pack('!BBHIIHHQ',self.version, self.type, self.plen, self.rid, self.aid, self.csum,
            self.autype, self.auth)
        return checksum(data, 0)


    def hdr(self, payload):
        self.plen = self.MIN_LEN + len(payload)
        self.csum = self.checksum()
        if self.type==pwospf.TYPE_HELLO:
            self.plen += 8
            return struct.pack('!BBHIIHHQII',self.version, self.type, self.plen, self.rid, self.aid, self.csum,
            self.autype, self.auth,self.netmask,self.helloint)

        if self.type==pwospf.TYPE_LSU:
            self.plen += 8 + self.nadv * 12
            format_string = "!BBHIIHHQHHI" + str(3 * self.nadv) + "I"

            return struct.pack(format_string,self.version, self.type, self.plen, self.rid, self.aid, self.csum,
            self.autype, self.auth,self.seq,self.ttl,self.nadv,*self.advList)

