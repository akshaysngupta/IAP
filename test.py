from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.node import Controller
import os

class POXBridge(Controller):
	def start(self):
		self.pox = '%s/pox/pox.py' % os.environ['HOME']
		self.cmd(self.pox,'forwarding.l2_learning &')
	def stop(self):
		"Stop POX"
		self.cmd('kill %' + self.pox)

controllers = {'poxbridge': POXBridge}

net = Mininet( controller=POXBridge )

print "Adding Hosts"
h1 = net.addHost('h1')
h2 = net.addHost('h2')
h3 = net.addHost('h3')
h4 = net.addHost('h4')
h5 = net.addHost('h5')
h6 = net.addHost('h6')

print "Adding Switchs"
s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')

r1 = net.addSwitch('r1')
r2 = net.addSwitch('r2')
r3 = net.addSwitch('r3')
r4 = net.addSwitch('r4')

print "Adding Links"
net.addLink(h1,s1)
net.addLink(h2,s1)
net.addLink(h3,r3)
net.addLink(h4,r2)
net.addLink(h5,s2)
net.addLink(h6,s2)

net.addLink(s1,r1)
net.addLink(s2,r4)

net.addLink(r1,r2)
net.addLink(r1,r3)
net.addLink(r2,r4)
net.addLink(r3,r4)

h1.setIP('10.0.1.2')
h2.setIP('10.0.1.3')
h3.setIP('10.0.3.2')
h4.setIP('10.0.2.2')
h5.setIP('10.0.4.2')
h6.setIP('10.0.4.3')

print "Starting Network"
net.start()
print "Dump"
dumpNodeConnections(net.hosts)
print "Test"
net.pingAll()
net.stop()
#CLI(net)
