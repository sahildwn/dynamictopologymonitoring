from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import switches, event, api
from ryu.lib import hub
from ryu.topology.api import get_switch, get_link, get_host
from ryu.app import simple_switch_13
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib

import copy
import networkx as nx
# import pylab
import matplotlib.pyplot as plt
import time
import sys

plt.ion()
wm = plt.get_current_fig_manager()
wm.window.wm_geometry("1366x768+50+50")
# mng.resize(*mng.window.maxsize())
plt.show()
centralGraph = nx.Graph()   #centralised network topology
numSecs = 1

#class SimpleSwitch13(app_manager.RyuApp):
class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stplib']


        self.firstPacket = True
        self.rawLinks = []
        self.rawLinks2= []
        self.switches = []
        self.hosts = []
        self.srcLinks = []
        self.dstLinks = []
        self.hostLinks = []
        self.usageList = []
        self.byteCounts = []
        self.prevByteCounts = []
        self.temp = []
        self.datapaths = {}
        self.pos = nx.spring_layout(centralGraph)

        config = {dpid_lib.str_to_dpid('0000000000000001'): {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'): {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000003'): {'bridge': {'priority': 0xa000}},
                  dpid_lib.str_to_dpid('0000000000000004'): {'bridge': {'priority': 0xb000}},
                  dpid_lib.str_to_dpid('0000000000000005'): {'bridge': {'priority': 0xc000}},
                  dpid_lib.str_to_dpid('0000000000000006'): {'bridge': {'priority': 0xd000}}
                  }
        self.stp.set_config(config)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        print("----------STATE CHANGE HANDLER================================-----")
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                print("----DATAAAAPAAATHIDDDD-=-=-=-=-=-=")
                print("----COLLLLLLECCCTING  DATAAAAPAAATHIDDDD-=-=-=-=-=-=")
                print(datapath.id)
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)

                del self.datapaths[datapath.id]

    def _monitor(self):
        print("----------INSIDE MONITORING FUNCTION----------")
        while True:
            print("----------MONITORING STARTED-----")
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(numSecs)
            temp = self.byteCounts
            label_dict = dict()
            if (len(self.prevByteCounts) != 0):
                self.byteCounts = [(x - y) for (x, y) in zip(self.byteCounts, self.prevByteCounts)]
                for i in range(0, len(self.rawLinks)):
                    label_dict[self.rawLinks[i]] = self.byteCounts[i]
                    print('there are {} bytes through link {}'.format(self.byteCounts[i], self.rawLinks[i]))
                print('\n')
            self.prevByteCounts = temp
            #plt.clf()
            print("===========================CONSTRUCTING GRAPH BASED ON MONITORING================================-----")
            nx.draw_networkx_edges(centralGraph, self.pos, node_color='A0CBE2', edge_cmap=plt.cm.Reds, ax=None, width=2, edge_color=self.byteCounts, edgelist=self.rawLinks)

            # the above command uses an argument edge_cmap where if there is too much traffic through the link, the color of the link becomes darker, in this case it will become dark red
            # also if there is less traffic through the link the color will be light for example orange
            # also note that the edge_color is set to self.byteCounts parameter which is basically the amount of traffic running between 2 switches

            nx.draw_networkx_edges(centralGraph, self.pos, node_color='A0CBE2', ax=None, width=2, edgelist=self.rawLinks2)
            nx.draw_networkx_edge_labels(centralGraph, self.pos, ax=None, edge_labels=label_dict, label_pos=0.5)
            nx.draw_networkx_nodes(centralGraph, self.pos, ax=None, nodelist=self.switches, node_size=1500, node_color='g')
            nx.draw_networkx_nodes(centralGraph, self.pos, ax=None, nodelist=self.hosts, node_size=1500, node_color='y')
            nx.draw_networkx_labels(centralGraph, self.pos, ax=None)
            plt.axis('off')
            time.sleep(0.01)
            #plt.pause(0.0001)
            plt.pause(0.0001)  # updates the graph periodically
            plt.clf()  # clears the plot for updating the traffic flowing through the switches
            plt.draw()  # matplotlib function to display the graph
            #plt.figure()
            self.byteCounts = [0] * len(self.rawLinks)

    def _request_stats(self, datapath):
        print("======================INSIDE REQUEST STATS FUNCTION===============================-----")
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        print("=======================INSIDE PORT STAT REPLY HANDLERRR================================-----")
        body = ev.msg.body
        print("BODYYYYY"+str(body))
        for stat in body:
            src_node = ev.msg.datapath.id
            print(">>>>>>>>>>>>>>>>>>>>SOURCE NODE FROM THE STATS<<<<<<<<<<<<<<<<<<<")
            print(src_node)
            src_port = stat.port_no
            print(">>>>>>>>>>>>>>>>>>>>>SOURCE PORT FROM THE STAT<<<<<<<<<<<<<<<<<<<<<")
            print(src_port)
            if (src_port == 4294967294):   #connection to controller, ignore for now
                continue
            if (src_port == 1):
                continue
            total_bytes = stat.tx_bytes + stat.rx_bytes
            print(">>>>>>>>>>>>>>>>>>>>>>>TOTAL BYTES<<<<<<<<<<<<<<<<<<<<<<")
            print(total_bytes)
            print("<<<<<<<<<<<<<<<<CALLING FINDLINK FUNCTION>>>>>>>>>>>>>>>>>>>>")
            pair = self.findLink(src_node, src_port, total_bytes)
            print(">>>>>>>>>>>>>>>>>>>>>>>PAIR VALUES<<<<<<<<<<<<<<<<<<<<")
            print(pair)
            print("<<<<<<<<<<<<<<<<<<<CALLING ADDBYTES FUNCTION>>>>>>>>>>>>>>>>>>>")
            self.addBytes(pair, total_bytes)

    def findLink(self, srcNode, srcPort, totalBytes):
        print(">>>>>>>>>>>>>>>>>>>INSIDE FINDLINK FUNCTION<<<<<<<<<<<<<<<<<<")
        #_ search through switch list
        print("printing SOURCENODE-->")
        print(srcNode)


        for elem in self.srcLinks:
            print("inside for loop of srclink!!!!!")
            print("now pringitng SRC          elem0 and 1 and srcnode and srcport and elem2 port")
            print(elem[0])
            print(elem[1])
            print(srcNode)
            print(srcPort)
            print(elem[2]['port'])
            if ((elem[1] == srcNode or elem[0] == srcNode) and elem[2]['port'] == srcPort):
                print("FIRST CONDITION SRC SUCCESSFULL!!!!! NOW RETURNIN ELEM 0 AND 1")
                print("now pringitng SRC    elem0 and 1 and srcnode and elem2 port")
                print(elem[0])
                print(elem[1])
                print(srcNode)
                print(elem[2]['port'])
                return (elem[0], elem[1])
            else:
                print("FIRST CONDITION UNSUCCESSFULLLL :(")
        for elem in self.hostLinks:
            print("SECOND CONDITION HOST SUCCESSFULL!!!!! ")
            print("now pringitng SRC          elem0 and 1 and srcnode and elem2 port")
            print(elem[0])
            print(elem[1])
            print(srcNode)
            print(elem[2]['port'])
            if (elem[1] == srcNode and elem[2]['port'] == srcPort):
                print("SECOND CONDITION S HOST SUCCESSFULL!!!!! NOW RETURNIN ELEM 0 AND 1")
                print("now pringitng  HOST        elem0 and 1 and srcnode and elem2 port")
                print(elem[0])
                print(elem[1])
                print(srcNode)
                print(elem[2]['port'])
                return (elem[0], elem[1])
            else:
                print("SECOND CONDITION UNSUCCESSFULLLL :(")
        print('not found (SOMETHING IS WRONG!)')
        return

    def addBytes(self, pair, totalBytes):
        i = 0
        print("----------ADDDDD BYTTTTTTESS-----")
        for rawPair in self.rawLinks:
            pairFlip = (pair[1], pair[0])
            if (pair == rawPair) or (pairFlip == rawPair):
                self.byteCounts[i] += totalBytes
                return
            i += 1
        print('could not add bytes (SOMETHING IS WRONG!')
        return

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("----------SWITCH FEATURE HANDLER!!-----")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # __ install table-miss flow entry
        # _
        #  _We specify NO BUFFER to max_len of the output action due to
        #  _OVS bug. At this moment, if we specify a lesser number, e.g.,
        #  _128, OVS will send Packet-In with invalid buffer_id and
        #  _truncated packet data. In that case, we cannot output packets
        #  _correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        print("----------ADDD FLOWWWWWWWW-----")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print(">>>>>>>>>>>>>>>>INSIDE PACKET_IN_HANDLER FUCNTION<<<<<<<<<<<<<<<<")
         # _If you hit this you might want to increase
         # _the "miss_send_length" of your switch
        if (self.firstPacket == True):
            self.monitor_thread = hub.spawn(self._monitor)   #only start monitor when controller is ready
            self.firstPacket = False
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
             #_ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

         #_learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

         #_install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
             # _verify if we have a valid buffer_id, if yes avoid to send both
             # _flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def get_topology_data(self, ev):
        print(">>>>>>>>>>>>>>>>>>INSIDE GET_TOPOLOGY_FUNCTION<<<<<<<<<<<<<<<")
        switchList = copy.copy(get_switch(self, None))
        print("printing switchlist")
        print(switchList)
        linkList = copy.copy(get_link(self, None))
        print("printing linklist")
        print(linkList)
        self.switches = [switch.dp.id for switch in switchList]
        print(">>>>>>>>>>>>>>>>>>>>SWITCH DATA FROM TOPOGET<<<<<<<<<<<<<<<<<<")
        print(self.switches)
        # print(self.switches)
        self.srcLinks = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in linkList]
        print(">>>>>>>>>>>>>>>>>>>>SOURCE LINKS FROM TOPOGET<<<<<<<<<<<<<<<<<<")
        print(link.src.dpid for link in linkList)
        print(self.srcLinks)
        self.dstLinks = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in linkList]
        print(">>>>>>>>>>>>>>>>>>>>DESTINATION LINKS FROM TOPOGET<<<<<<<<<<<<<<<<<<")
        print(self.dstLinks)
        self.constructGraph()

    def get_topology_data_wait(self, ev):
        time.sleep(0.5)   #need to wait here, switch is changing its openflow version
        self.get_topology_data(ev)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    def constructGraph(self):
        #plt.clf()
        print(">>>>>>>>>>>>>>>>>INSIDE CONSTRUCT_GRAPH FUNCTION<<<<<<<<<<<<<<<<<")
        centralGraph.clear()
        if (len(self.switches) == 0):   #deals with case of empty graph
             nx.draw(centralGraph)
             plt.draw()
        self.getRawData()
        centralGraph.add_nodes_from(self.switches)
        centralGraph.add_nodes_from(self.hosts)
        centralGraph.add_edges_from(self.rawLinks)
        centralGraph.add_edges_from(self.rawLinks2)
        self.pos = nx.spring_layout(centralGraph, k=0.15,iterations=20)
        nx.draw_networkx_nodes(centralGraph, self.pos, ax=None, nodelist=self.switches, node_size=1500, node_color='g')
        nx.draw_networkx_nodes(centralGraph, self.pos, ax=None, nodelist=self.hosts, node_size=1500, node_color='y')
        nx.draw_networkx_edges(centralGraph, self.pos, ax=None, width=1)
        nx.draw_networkx_labels(centralGraph, self.pos, ax=None)
        plt.axis('off')
        #nx.draw_networkx(centralGraph)
        time.sleep(0.1)
        plt.pause(0.0001) 
        plt.clf()
        plt.draw()
        #plt.figure()
        # plt.show()
        print("----------EXISTING construct-----")

    def getRawData(self):   #gets raw data for graph drawing
        print(">>>>>>>>>>>>>>>>>INSIDE RAW_DATA FUNCTION<<<<<<<<<<<<<<<<<")
        self.rawLinks = []
        raw1 = []
        raw2 = []
        for elem in self.srcLinks:
            if (elem[1], elem[0]) not in raw1:
                raw1.append((elem[0], elem[1]))
        raw2 = [(elem[1], elem[0]) for elem in self.hostLinks]
        print("----------------------RAW 1------------------------")
        print(raw1)
        print("---------------------RAW 2-----------------------")
        print(raw2)
        self.rawLinks = sorted(raw1)
        self.rawLinks2 = raw2
        print("--------------------RAWLINKS-------------------------------")
        print(self.rawLinks)
        self.byteCounts = [0] * len(self.rawLinks)
        print("-------------Exiting Raw Data-------")

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        print(">>>>>>>>>>>>>>>>>>>SWITCH HAS ENTERED<<<<<<<<<<<<<<<<<<<<<<<")
        self.get_topology_data_wait(ev)

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        self.get_topology_data_wait(ev)

    @set_ev_cls(event.EventHostAdd)
    def switch_leave_handler(self, ev):
        print("----------ADDING HOST INFO-----")
        hostList = copy.copy(get_host(self, None))
        self.hosts = [host.mac for host in hostList]
        print("------------HOSTS----------")
        print(self.hosts)
        self.hostLinks = [(host.mac, host.port.dpid, {'port': host.port.port_no, 'bytes': 0}) for host in hostList]
        print("----------HOSTSLINKS--------------------")
        print(self.hostLinks)
        self.get_topology_data(ev)

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])

