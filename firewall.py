#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import time


# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # Load the firewall rules (from rule_filename) here.
        self.rules = []
        lines = open(config['rule'], 'r')
        for line in lines:
            print line
            line = line.strip()
            if len(line) > 0 and line[0] != '%':
                self.rules.append(line)


        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        # The example code here prints out the source/destination IP addresses,
        # which is unnecessary for your submission.

        pkt_eval = self.evaluate_packet(pkt)

        packet_passed = self.evaluate_rules(pkt_dir, pkt)

        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
        
        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
        else:
            dir_str = 'outgoing'

        print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid,
                socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip))

        # ... and simply allow the packet.
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    # This evaluation is where we pretty much decipher the IP packet and return this evaluation
    # to the handle_rules part and see whether or not this packet is part of the rules
    # I think
    def evaluate_packet(self, pkt):
        if len(pkt) < 8:
            return None
        ip_eval = {}
        ip_eval['pass_pkt'] = True
        ip_eval['total_len'] = struct.unpack('!H', pkt[2:4])
        ip_eval['ttl'] = struct.unpack('!B', pkt[8:9])
        ip_eval['checksum'] = struct.unpack('!H', pkt[10:12])

        if len(pkt) != ip_eval['total_len']:
           ip_eval['pass_pkt'] = False
        if ip_eval['total_len'] < 5:
           ip_eval['pass_pkt'] = False

        if ip_eval['pass_pkt'] == True:
           ip_eval['src_ip'] = socket.inet_ntoa(pkt[12:16])
           ip_eval['dst_ip'] = socket.inet_ntoa(pkt[16:20])
           ip_eval['protocol'] = self.determine_protocol(ip_eval, pkt)


        return ip_eval

    # TODO: You can add more methods as you want.
    def determine_protocol(self, pkt):
        protocol = struct.unpack('B!', pkt[9:10])
        #ICMP
        if protocol == 1:
            pass
        #TCP
        elif protocol == 6:
            pass
        #DNS
        elif protocol == 17:
            pass
        return 'other'
        
    def make_tcp_packet(self):
        
        pass

    def make_dns_packet(self):
        pass


    def evaluate_rules(self, pkt_dir, pkt):
        # TODO: need to handle all rules here and determine for packet PASS/FAIL return type?
        verdict, protocol, ext_ip, ext_port, domain = None, None, None, None, None

        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]

        for rule in self.rules:
            rule = [r.lower() for r in rule.split()]

            if len(rule) == 4:
                print 'protocol ip rule'
                veridct = rule[0]
                protocol = rule[1]
                ext_ip = rule[2]
                ext_port = rule[3]
                
                transport = self.handle_transport(verdict, protocol, ext_ip, ext_port, pkt_dir, pkt)

            elif len(rule) == 3:
                print 'dns rule'
                verdict = rule[0]
                protocol = 'dns'
                domain = rule[2]

        return verdict
   
    def handle_transport(self, verdict, protocol, ext_ip, ext_port, pkt_dir, pkt):

        pkt_ext_ip = None
        if pkt_dir == PKT_DIR_OUTGOING:
            pkt_ext_ip = pkt[16:20]

        else:
            pkt_ext_ip = pkt[12:16]

        if self.evaluate_ip(ext_ip, pkt_ext_ip):
            pass
            


    def evaluate_ip(self, ext_ip, pkt_ext_ip):
        pass
    def evaluate_port(self):
        pass


# TODO: You may want to add more classes/functions as well.
