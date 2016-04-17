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

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "[PWOSPF: (Type: "+str(self.type) + ", Length: " + str(self.plen)+")]"

        return s

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

        length = self.plen
        self.next =  raw[pwospf.MIN_LEN:length]
        self.parsed = True

    def checksum(self):
        data = struct.pack('!BBHIIHHQ',self.version, self.type, self.plen, self.rid, self.aid, self.csum,
            self.autype, self.auth)
        return checksum(data, 0)


    def hdr(self, payload):
        self.plen = self.MIN_LEN + len(payload)
        self.csum = self.checksum()
        return struct.pack('!BBHIIHHQ',self.version, self.type, self.plen, self.rid, self.aid, self.csum,
            self.autype, self.auth)
