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

        packet_passed = self.evaluate_rules(pkt_dir, pkt_eval)

       # print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid,
       #         socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip))
        if packet_passed:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)

    # This evaluation is where we pretty much decipher the IP packet and return this evaluation
    # to the handle_rules part and see whether or not this packet is part of the rules
    def evaluate_packet(self, pkt):
        if len(pkt) < 8:
            return None
        ip_eval = {}
        ip_eval['version'] = struct.unpack('!B', pkt[0:1]) & 0b11110000
        ip_eval['header_len'] = struct.unpack('!B', pkt[0:1]) & 0b00001111
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


    # We check the ip packet and determine the protcol and create packets based off that.
    # Keep this function clean and simple
    def determine_protocol(self, ip_eval, pkt):
        protocol = struct.unpack('B!', pkt[9:10])

        #This is where the packet begins; since, for example if header length was 7,
        #the tcp packet starts at 7*4 bytes. so all the information like
        #src_port is essentially pkt[28:30]; treat this value as our 0 essentially
        header_start = ip_eval['header_len'] * 4
        #ICMP
        if protocol == 1:
            self.make_icmp_packet(ip_eval, pkt, header_start)
            return "icmp"
        #TCP
        elif protocol == 6:
            self.make_tcp_packet(ip_eval, pkt, header_start)
            return 'tcp'

        #DNS is a UDP packet, but if this isnt a DNS, then we want to just return a UDP packet 
        elif protocol == 17:
            ip_eval['src_port'] = struct.unpack('H!', pkt[header_start:header_start + 2])
            ip_eval['dst_port'] = struct.unpack('H!', pkt[header_start + 2:header_start + 4])
            if ip_eval['dst_port'] == 53:
                self.make_dns_packet(ip_eval, pkt, header_start)
                return 'dns'
            ip_eval['udp_len'] = struct.unpack('H!', pkt[header_start + 4:header_start + 6])
            ip_eval['checksum'] = struct.unpack('H!', pkt[header_start + 6:header_start + 8])

            return 'udp'
        return 'other'
    
    def make_icmp_packet(self, ip_eval, pkt, header_start):
        ip_eval['type'] = struct.unpack('B!', pkt[header_start:header_start+1])
        ip_eval['code'] = struct.unpack('B!', pkt[header_start+1: header_start + 2])
        ip_eval['checksum'] = struct.unpack('H!', pkt[header+2:header_start+4])

        # TODO: (not sure if 3B) but theres an 'others' leftover, not sure what this means, will have to
        # look into it
        
    def make_tcp_packet(self, ip_eval, pkt, header_start):
        # TODO: add the other stuff, but i think for 3a we just care about src_port and dst_port
        ip_eval['src_port'] = struct.unpack('H!', pkt[header_start:header_start + 2])    
        ip_eval['dst_port'] = struct.unpack('H!', pkt[header_start + 2: header_start + 4])
        ip_eval['seq_num'] = struct.unpack('L!', pkt[header_start + 4: header_start + 8])
        ip_eval['ack_num'] = struct.unpack('L!', pkt[header_start + 8: header_start + 12])
        
        offset_reserved = struct.unpack('B!', pkt[header_start + 12: header_start + 13])
        offset = 0b11110000 & offset_reserved
        reserved = 0b00001111 & offset_reserved

        flags = struct.unpack('B!', pkt[header_start + 13: header_start + 14])
        #TODO: (PROJECT 3B) deal with this flag nonsense


    def make_dns_packet(self, ip_eval, pkt, header_start):
        #TODO: make dns packet here
        pass
        

    # So evaluate all the rules in the config for each packet. If we find a match,
    # look at the verdict, use this, otherwise, just pass the packet.
    # we want to return some sort of indicator to send this packet or not
 
    def evaluate_rules(self, pkt_dir, pkt_eval):
        # TODO: need to handle all rules here and determine for packet PASS/FAIL return type?
        verdict, protocol, ext_ip, ext_port, domain = None, None, None, None, None

        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]

        pass_packet = False
        for rule in self.rules:
            rule = [r.lower() for r in rule.split()]

            if len(rule) == 4:
                print 'protocol ip rule'
                veridct = rule[0]
                protocol = rule[1]
                ext_ip = rule[2]
                ext_port = rule[3]

                ip_check = self.check_external_ip(ext_ip, pkt_dir, pkt)
                check_protocol = False
                if pkt_eval['protocol'] == protocol:
                    check_protocol = True
                port_check = self.check_external_port(ext_port, pkt_dir, pkt)

            elif len(rule) == 3:
                print 'dns rule'
                verdict = rule[0]
                protocol = 'dns'
                domain = rule[2]

   
    # Check to see if the IPs match
    # if it doesnt, then we missed the match and this packet will be dropped
    def check_external_ip(self, ext_ip, pkt_dir, pkt):
        pkt_ext_ip = None
        if pkt_dir == PKT_DIR_OUTGOING:
            pkt_ext_ip = pkt[16:20]
        else:
            pkt_ext_ip = pkt[12:16]

        if ext_ip == 'any':
            return True
        elif len(ext_ip) == 2:
            pass
        elif self.evaluate_ip(ext_ip, pkt_ext_ip):
            return True 
        elif '/' in ext_ip:
            # Check for netmask thing here
            pass
        else:
            return False
    
    # Check if the port is valid
    def check_external_port(self, ext_port, pkt_dir, pkt):
        pass

    def evaluate_ip(self, ext_ip, pkt_ext_ip):
        if ext_ip == pkt_ext_ip:
            return True
        pass
    def evaluate_port(self):
        pass


# TODO: You may want to add more classes/functions as well.
