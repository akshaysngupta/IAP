from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.node import Controller
from mininet.topo import Topo
import os

class POXBridge(Controller):
	def start(self):
		print "POX Controller Started"
		self.pox = '%s/pox/pox.py' % os.environ['HOME']
		self.cmd(self.pox,'misc.controller &')
	def stop(self):
		print "Stop POX"
		self.cmd('kill %' + self.pox)

controllers = {'poxbridge': POXBridge}

class MyTopo(Topo):

	def __init__(self):

		Topo.__init__(self)

		print "Adding Hosts"
		h1 = self.addHost('h1',ip='10.0.1.2',defaultRoute='via 10.0.1.1')
		h2 = self.addHost('h2',ip='10.0.1.3',defaultRoute='via 10.0.1.1')
		h3 = self.addHost('h3',ip='10.0.3.2',defaultRoute='via 10.0.3.1')
		h4 = self.addHost('h4',ip='10.0.2.2',defaultRoute='via 10.0.2.1')
		h5 = self.addHost('h5',ip='10.0.4.2',defaultRoute='via 10.0.4.1')
		h6 = self.addHost('h6',ip='10.0.4.3',defaultRoute='via 10.0.4.1')

		print "Adding Switchs"
		s1 = self.addSwitch('s1')
		s2 = self.addSwitch('s2')

		r1 = self.addSwitch('r1')
		r2 = self.addSwitch('r2')
		r3 = self.addSwitch('r3')
		r4 = self.addSwitch('r4')

		print "Adding Links"
		self.addLink(h1,s1)
		self.addLink(h2,s1)
		self.addLink(h3,r3)
		self.addLink(h4,r2)
		self.addLink(h5,s2)
		self.addLink(h6,s2)

		self.addLink(s1,r1)
		self.addLink(s2,r4)

		self.addLink(r1,r2)
		self.addLink(r1,r3)
		self.addLink(r2,r4)
		self.addLink(r3,r4)

topos = { 'mytopo': ( lambda:MyTopo() ) }
