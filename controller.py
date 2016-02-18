from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time

log = core.getLogger()

switch_list = {"00-00-00-00-00-01","00-00-00-00-00-02"}

class FloodSwitch (object):
  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)

  def _handle_PacketIn (self, event):
    packet = event.parsed

    def flood (message = None):
      log.debug("Switch %s %s"% (dpid_to_str(event.dpid),event.dpid))
      log.debug("Flooding!!")
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    flood(packet)

class StaticRouter (object):
  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)

  def _handle_PacketIn (self, event):
    packet = event.parsed
    def flood (message = None):
      log.debug("Router %s %s"% (dpid_to_str(event.dpid),event.dpid))
      log.debug("Flooding!!")
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)
    flood(packet)

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
