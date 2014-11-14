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

        self.geo_ips = []
        geo_lines = open('geoipdb.txt')
        for line in geo_lines:
            line = line.strip()
            if len(line) > 0 and line[0] != '%':
                self.geo_ips.append(line)


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
        ip_eval['version'] = struct.unpack('!B', pkt[0:1])[0] & 0b11110000
        ip_eval['header_len'] = struct.unpack('!B', pkt[0:1])[0] & 0b00001111
        ip_eval['pass_pkt'] = True
        ip_eval['total_len'] = struct.unpack('!H', pkt[2:4])[0]
        ip_eval['ttl'] = struct.unpack('!B', pkt[8:9])[0]
        ip_eval['checksum'] = struct.unpack('!H', pkt[10:12])[0]

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
        protocol = struct.unpack('!B', pkt[9:10])[0]

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
            ip_eval['src_port'] = struct.unpack('!H', pkt[header_start:header_start + 2])[0]
            ip_eval['dst_port'] = struct.unpack('!H', pkt[header_start + 2:header_start + 4])[0]
            ip_eval['udp_len'] = struct.unpack('!H', pkt[header_start + 4:header_start + 6])[0]
            ip_eval['checksum'] = struct.unpack('!H', pkt[header_start + 6:header_start + 8])[0]
            if ip_eval['dst_port'] == 53:
                self.make_dns_packet(ip_eval, pkt, header_start)
                return 'dns'
            return 'udp'
        return 'other'
    
    def make_icmp_packet(self, ip_eval, pkt, header_start):
        ip_eval['type'] = struct.unpack('!B', pkt[header_start:header_start+1])[0]
        ip_eval['code'] = struct.unpack('!B', pkt[header_start+1: header_start + 2])[0]
        ip_eval['checksum'] = struct.unpack('!H', pkt[header+2:header_start+4])[0]

        # TODO: (not sure if 3B) but theres an 'others' leftover, not sure what this means, will have to
        # look into it
        
    def make_tcp_packet(self, ip_eval, pkt, header_start):
        # TODO: add the other stuff, but i think for 3a we just care about src_port and dst_port
        ip_eval['src_port'] = struct.unpack('!H', pkt[header_start:header_start + 2])[0]
        ip_eval['dst_port'] = struct.unpack('!H', pkt[header_start + 2: header_start + 4])[0]
        ip_eval['seq_num'] = struct.unpack('!L', pkt[header_start + 4: header_start + 8])[0]
        ip_eval['ack_num'] = struct.unpack('!L', pkt[header_start + 8: header_start + 12])[0]
        
        offset_reserved = struct.unpack('!B', pkt[header_start + 12: header_start + 13])[0]
        offset = 0b11110000 & offset_reserved
        reserved = 0b00001111 & offset_reserved

        flags = struct.unpack('!B', pkt[header_start + 13: header_start + 14])[0]
        #TODO: (PROJECT 3B) deal with this flag nonsense


    def make_dns_packet(self, ip_eval, pkt, header_start):
        ip_eval['qdcount'] = struct.unpack('!H', pkt[header_start + 12: header_start + 14])[0]
        i, j = 0, 0
        qname_list = []
        while struct.unpack('!B', pkt[header_start + 20 + i: header_start + 21 + i])[0] != 0:
            if j == 0:
                j = struct.unpack('!B', pkt[header_start + 20 + i: header_start + 21 + i])[0]
                qname_list.append(0x2e)
            else:
                j -= 1
                qname_list.append(struct.unpack('!B', pkt[header_start + 20 + i: header_start + 21 + i])[0])
            i += 1
        if len(qname_list) > 0:
            qname_list.remove(0x2e)
        ip_eval['qname'] = ''.join(chr(i) for i in qname_list)
        ip_eval['qtype'] = struct.unpack('!H', pkt[header_start + 21 + i: header_start + 23 + i])[0]
        ip_eval['qclass'] = struct.unpack('!H', pkt[header_start + 23 + i: header_start + 25 + i])[0]

    # So evaluate all the rules in the config for each packet. If we find a match,
    # look at the verdict, use this, otherwise, just pass the packet.
    # we want to return some sort of indicator to send this packet or not
 
    def evaluate_rules(self, pkt_dir, pkt_eval):
        # TODO: need to handle all rules here and determine for packet PASS/FAIL return type?
        verdict, protocol, ext_ip, ext_port, domain = None, None, None, None, None
        match_found = False
        final_verdict = None

        # src_ip = pkt[12:16]
        # dst_ip = pkt[16:20]

        pass_packet = False
        for rule in self.rules:
            rule = [r.lower() for r in rule.split()]

            if len(rule) == 4:
                verdict = rule[0]
                protocol = rule[1]
                ext_ip = rule[2]
                ext_port = rule[3]

                ip_check = self.check_external_ip(ext_ip, pkt_dir, pkt_eval)
                check_protocol = False
                if pkt_eval['protocol'] == protocol:
                    check_protocol = True
                port_check = self.check_external_port(ext_port, pkt_dir, pkt_eval)
                '''print '\n-------current packet-------'
                print 'protocol:', pkt_eval['protocol']
                print '\n-------Current rules----'
                print 'verdict:', verdict, ' protocol:', protocol, ' ext_ip:', ext_ip, ' ext_port:', ext_port
                print '\n-----Current checks-----'
                print 'ip_check: ', ip_check, 'protocol_check:', check_protocol, ' port check:', port_check
                '''
                
                if ip_check and check_protocol and port_check:
                    print 'MATCHED'
                    match_found = True
                    final_verdict = verdict

            elif len(rule) == 3:
                verdict = rule[0]
                protocol = 'dns'
                domain = rule[2]
                if pkt_eval['protocol'] == protocol:
                    dns_ok = self.check_dns(pkt_dir, pkt_eval)
                    if dns_ok:
                        if domain[0] == '*':
                            if len(domain) == 1:
                                final_verdict = verdict
                                match_found = True
                            else:
                                mask_len = len(domain) - 1
                                qname_len = len(pkt_eval['qname'])
                                print pkt_eval['qname']
                                print "\n\n\n"
                                if pkt_eval['qname'][qname_len - mask_len:] == domain[1:]:
                                    final_verdict = verdict
                                    match_found = True
                        else:
                            if domain == pkt_eval['qname']:
                                final_verdict = verdict
                                match_found = True


        if not match_found:
            return True
        else:
            if final_verdict == 'pass':
                return True
            return False

    # Check to see if DNS preconditions for valid packet are satisfied
    def check_dns(self, pkt_dir, pkt_eval):
        return (pkt_eval['qdcount'] == 1) and ((pkt_eval['qtype'] == 1) or (pkt_eval['qtype'] == 28)) and (pkt_eval['qclass'] == 1)
   
    # Check to see if the IPs match
    # if it doesnt, then we missed the match and this packet will be dropped
    def check_external_ip(self, ext_ip, pkt_dir, pkt_eval):
        pkt_ext_ip = None
        if pkt_dir == PKT_DIR_OUTGOING:
            pkt_ext_ip = pkt_eval['dst_ip']
        else:
            pkt_ext_ip = pkt_eval['src_ip']
        if ext_ip == 'any':
            return True
        elif len(ext_ip) == 2:
            # Check for geoip db stuff here
            print pkt_ext_ip
            pkt_ext_ip = struct.unpack('!L', socket.inet_aton(pkt_ext_ip))
            return self.evaluate_geoip(pkt_ext_ip, self.geo_ips) == ext_ip.lower()
             
        elif ext_ip == str(pkt_ext_ip):
            return True 
        elif '/' in ext_ip:
            ip_netmask = ext_ip.split('/')
            pkt_ext_ip = struct.unpack('!L', socket.inet_aton(pkt_ext_ip))
            ip = struct.unpack('!L', socket.inet_aton(ip_netmask[0]))
            netmask = struct.unpack('!L', socket.inet_aton(ip_netmask[1]))

            bounds_ip = struct.unpack('!L', socket.inet_aton(ip + (32 - (int(netmask)**2 - 1))))
            
            if ip <= pkt_ext_ip and pkt_ext_ip <= bounds_ip:
                return True
            return False

        else:
            return False

    # Do a Binary search to find a match; if found, we can can return True for checking the ip
    def evaluate_geoip(self, pkt_ext_ip, geo_ips):
        if len(geo_ips) == 0:
            return None
        elif len(geo_ips) == 1:
            ip_range = geo_ips[0].split()
            lower = struct.unpack('!L', socket.inet_aton(ip_range[0]))
            upper = struct.unpack('!L', socket.inet_aton(ip_range[1]))
            if pkt_ext_ip >= lower and pkt_ext_ip <= upper:
                return ip_range[2]
        
        middle = len(geo_ips) / 2
        ip_range = geo_ips[middle].split()

        lower = struct.unpack('!L', socket.inet_aton(ip_range[0]))
        upper = struct.unpack('!L', socket.inet_aton(ip_range[1]))
        if pkt_ext_ip >= lower and pkt_ext_ip <= upper:
            return ip_range[2]

        if pkt_ext_ip > upper:
            return self.evaluate_geoip(pkt_ext_ip, geo_ips[middle+1:])
        else:
            return self.evaluate_geoip(pkt_ext_ip, geo_ips[0:middle])
        
    
    # Check if the port is valid
    def check_external_port(self, ext_port, pkt_dir, pkt_eval):
        pkt_ext_port = None

        if pkt_dir == PKT_DIR_OUTGOING:
            pkt_ext_port = pkt_eval['dst_port'] 
        else:
            pkt_ext_port = pkt_eval['src_port']

        if pkt_eval['protocol'] == 'icmp':
            #TODO: something else specific to icmp
            pkt_ext_port = pkt_eval['type']
        if ext_port == 'any':
            return True

        elif '-' in ext_port:
            range_ports = ext_port.split('-')
            if int(range_ports[0]) <= pkt_ext_port and int(range_ports[1]) >= pkt_ext_port:
                return True
            return False
        elif ext_port.isdigit():
            return str(pkt_ext_port) == ext_port


# TODO: You may want to add more classes/functions as well.
