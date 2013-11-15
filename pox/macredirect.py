# Copyright 2013 <Your Name Here>
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

"""
A skeleton POX component

You can customize this to do whatever you like.  Don't forget to
adjust the Copyright above, and to delete the Apache license if you
don't want to release under Apache (but consider doing so!).

Rename this file to whatever you like, .e.g., mycomponent.py.  You can
then invoke it with "./pox.py mycomponent" if you leave it in the
ext/ directory.

Implement a launch() function (as shown below) which accepts commandline
arguments and starts off your component (e.g., by listening to events).

Edit this docstring and your launch function's docstring.  These will
show up when used with the help component ("./pox.py help --mycomponent").
"""

# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library
import pox.messenger as messenger
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer

log = core.getLogger()

class MAC_Filter(messenger.ChannelBot):
  def __init__(self):
    core.listen_to_dependencies(self, components=['MessengerNexus'])
    #self.connection = connection
    self.blocked = ['00:16:3e:41:75:ed']
    self.dmz = '00:16:3e:04:0d:b7'
    self.actionhandle = "forward"
    self.hackers = {
      'hacker02':'00:16:3e:5e:21:83',
      'hacker04':'00:16:3e:65:b9:5a',
      'hacker01':'00:16:3e:41:5c:55',
      'hacker03':'00:16:3e:72:ab:44'
    }
    
    self.bad_src = [ self.hackers[i] for i in self.hackers ]

  def _all_dependencies_met (self):
    self._startup("mac_redir")

    # Periodically just send a topo
    #self.timer = Timer(10, self.send_table, recurring=True)
    log.debug("Ready to rip.")

  def send_table (self):
    if self.pending: return
    self.pending = True
    Timer(.2, self._do_send_table, recurring=False)

  def _do_send_table (self):
    assert self.pending
    self.pending = False
    switches = {}
    for s in self.switches:
      switches[s] = {'label':s}
    edges = []
    for e in self.links:
      if e[0] not in switches: continue
      if e[1] not in switches: continue
      edges.append(e)

    #print self.switches,switches
    #print self.links,edges

    self.send(topo={'links':edges,'switches':switches})

  #def _handle_openflow_PacketIn(self, event):
  def _handle_PacketIn(self, event):
    packet = event.parsed
    #log.info("Got %s | %s" % (repr(packet.dst), repr(self.blocked)))

    if str(packet.dst) in self.blocked:
      if self.actionhandle == "redirect":
        log.info("Forwarding %s toward %s" % (packet.dst, self.dmz))
        msg = of.ofp_packet_out()
        msg = of.ofp_flow_mod()
        action = of.ofp_action_dl_addr.set_dst(EthAddr(self.dmz))
        msg.actions.append(action)
        self.connection.send(msg)
      elif self.actionhandle == "block":
        if str(packet.src) in self.bad_src:
          log.info("Blocking %s toward %s" % (packet.src, packet.dst))
          return revent.EventHalt
      elif self.actionhandle == "forward":
        log.info("Forwarding .......")

  def _handle_openflow_ConnectionUp (self, event):
    #print "CU"
    log.info("Controlling %s" % event.connection)
    event.connection.addListeners(self)

  def _exec_cmd_status_hackers(self, event):
    self.send(status = (self.actionhandle))

  def _exec_cmd_release_hackers(self, event):
    log.info("Allowing bad macs (meh)")
    self.actionhandle = "forward"
    self.send(status = ("allowed"))

  def _exec_cmd_block_hackers(self, event):
    log.info("Stopping bad macs")
    self.actionhandle = "block"
    self.send(status = ("blocking"))

@poxutil.eval_args
def launch ():
  """
  The default launcher just logs its arguments
  """
  #core.addListenerByName("UpEvent", _go_up)
  core.registerNew(MAC_Filter)
