# Copyright (C) 2014 SDN Hub
#
# Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
# You may not use this file except in compliance with this License.
# You may obtain a copy of the License at
#
#    http://www.gnu.org/licenses/gpl-3.0.txt
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.

import logging
import random

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.ofproto import ether, inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import arp

DEFAULT_IDLE_TIMEOUT = 60
DEFAULT_HARD_TIMEOUT = 300

LOG = logging.getLogger('ryu.app.sdnhub_apps.learning_switch')

class L2LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2LearningSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.exemption = []
        self.switch_flows = {}

    def get_switch_flows(self):
        return self.switch_flows

    def get_switch_flows(self, dpid):
        return self.switch_flows[dpid]

    def add_exemption(self, match=None):
        if match != None:
            self.exemption.append(match)

    def clear_exemption(self):
        del self.exemption[:]

    def get_attachment_port(self, dpid, mac):
        if dpid in self.mac_to_port:
            table = self.mac_to_port[dpid]
            if mac in table:
                return table[mac]

        return None

    '''def is_packet_exempted(self, pkt):
        fields = {}
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        fields['dl_src'] = eth.src
        fields['dl_dst'] = eth.dst
        fields['dl_type'] = eth.ethertype

        if eth.ethertype == ether.ETH_TYPE_ARP:
            arp_hdr = pkt.get_protocols(arp.arp)[0]
            fields['nw_src'] = arp_hdr.src_ip
            fields['nw_dst'] = arp_hdr.dst_ip

        elif eth.ethertype == ether.ETH_TYPE_IP:
            ip_hdr = pkt.get_protocols(ipv4.ipv4)[0]
            fields['nw_src'] = ip_hdr.src
            fields['nw_dst'] = ip_hdr.dst
            fields['nw_proto'] = ip_hdr.proto

            if ip_hdr.proto == inet.IPPROTO_TCP:
                tcp_hdr = pkt.get_protocols(tcp.tcp)[0]
                fields['tp_src'] = tcp_hdr.src_port
                fields['tp_dst'] = tcp_hdr.dst_port
            elif ip_hdr.proto == inet.IPPROTO_UDP:
                tcp_hdr = pkt.get_protocols(tcp.tcp)[0]
                fields['tp_src'] = tcp_hdr.src_port
                fields['tp_dst'] = tcp_hdr.dst_port
        
        for match in self.exemption:
            # the match specified for exemption should be a
            # superset of the flows to exclude processing. 
            superset = True

            for key,val in match.iteritems():
                if key not in fields:
                    superset = False
                    break
                elif val != fields[key]:
                    superset = False
                    break

            # This exemption rule matched
            if superset:
                return True'''
        

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        cookie = random.randint(0, 0xffffffffffffffff)

        mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=priority,table_id=100, cookie=cookie,
                match=match, instructions=inst)
	
        datapath.send_msg(mod)

        match_str = ofctl_v1_3.match_to_str(match),
        self.switch_flows[datapath.id].append({'cookie':cookie,
                                               'match':match_str,
                                               'actions':actions,
                                               'priority':priority})

        LOG.debug("Flow inserted to switch %x: cookie=%s, match=%s, actions=%s, priority=%d",
                                  datapath.id, str(cookie), match_str, str(actions), priority)


    def del_all_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, match=parser.OFPMatch(), table_id=ofproto.OFPTT_ALL, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, priority=0)
        datapath.send_msg(msg)

    def send_barrier_request(self, datapath):
	datapath.send_msg(datapath.ofproto_parser.OFPBarrierRequest(datapath))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        assert datapath is not None

        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
	self.logger.info('in switch_features_handler')

        self.mac_to_port.setdefault(datapath.id, {})
        self.switch_flows.setdefault(datapath.id, [])

        # install table-miss flow entry
	self.del_all_flows(datapath)
	self.send_barrier_request(datapath)
	if datapath.id == 3342545872144448 or datapath.id == 3342545872095552:		
        	match = ofp_parser.OFPMatch()
        	actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        	self.add_flow(datapath, 0, match, actions)

	else:
		match = ofp_parser.OFPMatch(in_port=7)
		actions = [ofp_parser.OFPActionOutput(8)]
		self.add_flow(datapath, 1, match, actions)
		match = ofp_parser.OFPMatch(in_port=8)
		actions = [ofp_parser.OFPActionOutput(7)]
		self.add_flow(datapath, 1, match, actions)
		
		


        if ev.state == DEAD_DISPATCHER:
            if datapath.id != None:
                del self.mac_to_port[datapath.id]
                del self.switch_flows[datapath.id]


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        '''if self.is_packet_exempted(pkt):
            return'''

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        # Skip processing LLDP packets. Leave it to the topology module
        if eth.ethertype == ether.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
	self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # Learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # Following is an optimization to stop troubling the controller
        # too often. But, it has an effect of preventing the controller
        # from seeing a few hosts because the ARP reply matches this
        # rule and goes hidden from controller.

        # On packet_in for any packet, program a low priority rule for
        # the destination MAC so that we don't keep troubling controller
        # actions = [ofp_parser.OFPActionOutput(in_port)]
        # match = ofp_parser.OFPMatch(eth_dst=src)
        # self.add_flow(datapath=datapath, priority=1,
        #              match=match, actions=actions) 

        # Learning switch logic below
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [ofp_parser.OFPActionOutput()]

        # install a flow to avoid packet_in next time
        if in_port != 7 or 8:
            match = ofp_parser.OFPMatch(in_port=in_port)
            self.add_flow(datapath, 1, match, actions)

            # Are we done, or do we need to forward this packet?
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                return

        # For the case of ARP packets and unknown destination, just do
        # single packet-out with the same action
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        out = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    '''@set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        cookie = msg.cookie
        match_str = ofctl_v1_3.match_to_str(msg.match)
        index_to_delete = None

        # Ensure that the flow removed is for a known switch
        if dpid not in self.switch_flows:
            return

        for index, flow in enumerate(self.switch_flows[dpid]):
            if flow['cookie'] == cookie:
                index_to_delete = index
                break

        if index_to_delete is not None:
            del self.switch_flows[dpid][index_to_delete]
            LOG.debug("Flow removed on switch %d: match=%s, cookie=%s",
                    dpid, match_str, cookie)'''
