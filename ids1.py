import logging
import socket, sys
from scapy.all import *
from scapy.error import Scapy_Exception
from scapy.all import sr1,IP,ICMP
from scapy.all import srp
from scapy.all import Ether, ARP, conf
import sqlite3
import os
import sys
import threading
from threading import Thread
from optparse import OptionParser
import signal
from struct import *
import time
import pyshark

logging.basicConfig(filename='ids.log',level=logging.DEBUG)

time_current = time.strftime("%I:%M:%S")
logging.info('%s' % time_current)
date_current = time.strftime("%d/%m/%Y\n")
logging.info('%s' % date_current)

counter = 0
attacker_L2 = ''
attacker_MAC = ''
victim_MAC = ''
victim_L3 = ''

conn = sqlite3.connect('IDSDB.db')
C = conn.cursor()
query = "DELETE FROM ARPRequests;"
C.execute(query)
query = "DELETE FROM ARPCache;"
C.execute(query)
conn.commit()
conn.close()

GATEWAY_IP = raw_input("\nEnter your Gateway IP: ")
logging.info('Gateway IP: %s' % GATEWAY_IP)

interface = raw_input("\nEnter your Network Interface: ")
logging.info('Interface: %s' % interface)

n_range = raw_input("\nEnter your network range to defend (in format 10.0.0.1/24): ")
logging.info('Network range to defend: %s' % n_range)

def manage_db():
	try:
		conn = sqlite3.connect('IDSDB.db')
		#print("Opened DB")
		return conn
    	
	except:
		print("DB Error\n")
		sys.exit(2)

def get_mac_gateway(ip_address):
    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
        timeout=2, retry=2)
        
    for s, r in response:
        return r[Ether].src
    return None

    logging.info('Gateway : %s' % r[Ether].src)
    global GATEWAY_MAC 
    GATEWAY_MAC = "%s" % r[Ether].src

def arp_network_range(iprange="%s" % n_range):

    logging.info('Sending ARPs to network range %s' % n_range)
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=iprange), timeout=5)

    collection = []
    for snd, rcv in ans:
    	#print("Send = ", snd, " Recv = ", rcv)
    	result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()
    	logging.info('%s' % result)
    	collection.append(result)
	#print("Collection ", collection)
    return collection

def exist(ip):
	conn = sqlite3.connect('IDSDB.db')
	C = conn.cursor()
	query = "SELECT IP FROM ARPRequests;"
	for add in C.execute(query):
		if add == ip:
			conn.close()
			return False
	conn.close()
	return True

def initialize_tables(elements):
	for element in elements:
		#print(element[0] + " : " + element[1])
		if exist(element[0]):
			query1 = "INSERT INTO ARPRequests(MAC, IP) VALUES('"+ element[1]+ "', '" + element[0] + "');"
			#print("Query : " + query1)
			CONN.execute(query1)
			query2 = "INSERT INTO ARPCache(MAC, IP, LIFETIME, DANGEROUS) VALUES('"+ element[1]+ "', '" + element[0] + "', datetime('now'), 0);"
			#print("Query : " + query2)
			CONN.execute(query2)
			CONN.commit()

def check_intrusion_request(packet):
	#Extracting ip address and mac address of self
	self_ip = 'ifconfig ' + interface + ' | grep "inet"'
	f = os.popen(self_ip)
	src_ip = f.read()
	self_ip = src_ip[13:28]
	self_mac = 'ifconfig ' + interface + ' | grep "ether"'
	f = os.popen(self_mac)
	src_mac = f.read()
	self_mac = src_mac[14:31]
	
	conn = sqlite3.connect('IDSDB.db')
	C = conn.cursor()
		
	if packet[ARP].op == 1:
		#If the Request is for Self, Send Response
		if packet[ARP].pdst == self_ip:
			print("*** Request for Self, Sending ARP Response....")
			ans, unans = srp(Ether(dst=packet[ARP].psrc)/ARP(op=ARP.is_at, pdst=packet[ARP].psrc, hwsrc=self_mac , hwdst=packet[ARP].hwsrc, psrc=packet[ARP].pdst), timeout=5)
			collection = []
			
			for snd, rcv in ans:
				result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()
				logging.info('%s' % result)
				collection.append(result)
			initialize_tables(collection)
				
		#Else add the new ip, mac pair to ARPCache table
		else:
			if exist(packet[ARP].pdst):
				query = "INSERT INTO ARPRequests(MAC, IP) VALUES('"+ packet[ARP].hwsrc + "', '" + packet[ARP].pdst + "');"
				conn.execute(query)
				conn.commit()
			
		flag = 0
		query = "SELECT IP FROM ARPCache;"
		
		for row in C.execute(query):
			if row == packet[ARP].psrc:
				flag = 1
				
		if flag == 0:
			query = "SELECT IP, MAC FROM ARPCache;"
			for ip, mac in C.execute(query):
			#If sender ip is already cached and mac is matching, do nothing
				if ip == packet[ARP].psrc:
					if mac == packet[ARP].hwsrc:
						conn.close()
						return
			#Else, mark entry as dangerous
					else:
						query = "UPDATE ARPCache SET DANGEROUS = 1;"
						C.execute(query)
						conn.commit()
						conn.close()
						return
		
		
def check_intrusion_reply(packet):
	#Extracting ip address and mac address of self
	self_ip = 'ifconfig ' + interface + ' | grep "inet"'
	f = os.popen(self_ip)
	src_ip = f.read()
	self_ip = src_ip[13:28]
	self_mac = 'ifconfig ' + interface + ' | grep "ether"'
	f = os.popen(self_mac)
	src_mac = f.read()
	self_mac = src_mac[14:31]
	conn = sqlite3.connect('IDSDB.db')
	C = conn.cursor()
	
	query = "SELECT IP, MAC, DANGEROUS FROM ARPCache;"
	for ip, mac, dangerous in C.execute(query):
	#If the entry is marked as dangerous Combat
		if ip == packet[ARP].psrc:
			if dangerous == 1:
				print("\033[91m" + "\n<<ARP Reply recieved without sending ARP Request. Attempted Man-in-the-Middle Attack : ARP Poisoning detected.>>" + "\033[0m")
			else:
				if exist(packet[ARP].psrc):
					query = "INSERT INTO ARPCache(MAC, IP, LIFETIME, DANGEROUS) VALUES('"+ packet[ARP].hwsrc + "', '" + packet[ARP].psrc + "', datetime('now'), 0);"
					conn.execute(query)
					conn.commit()
				return
		
		#If the reply is received without sending out a request, Display warning
	flag = 0
	query = "SELECT IP, MAC FROM ARPRequests;"
	for ip, mac in C.execute(query):
		if ip == packet[ARP].psrc or self_ip == packet[ARP].psrc:
			flag = 1
		else:
			if flag == 0:
				print("\033[91m" + "\n<<ARP Reply recieved without sending ARP Request. Attempted Man-in-the-Middle Attack : ARP Poisoning detected.>>" + "\033[0m")
	conn.close()
	return
			

def arp_display(packet):
	if packet[ARP].op == 1:
		check_intrusion_request(packet)
		logging.info('[*] Probe- %s is asking for L2 of %s' % (packet[ARP].psrc, packet[ARP].pdst))
		return '*** ARPREQUEST : From Source %s , For Destination %s' % (packet[ARP].psrc, packet[ARP].pdst)
	if packet[ARP].op == 2:
		check_intrusion_reply(packet)
		logging.info('[*] Response- %s L3 address is %s' % (packet[ARP].hwsrc, packet[ARP].psrc))
		return '*** ARPRESPONSE : MAC - %s, IP - %s' % (packet[ARP].hwsrc, packet[ARP].psrc)
		
		

def sniff_arps():
	sniff(filter = "arp", prn = arp_display)
	
'''def examine_packet(packet):
	if packet is :
		print("No Packet Received")'''
		

if __name__ == '__main__':

    GATEWAY_MAC = get_mac_gateway(GATEWAY_IP)
    print("*** Gateway %s is at %s" % (GATEWAY_IP, GATEWAY_MAC))
    
    elements = arp_network_range()
    global CONN
    CONN = manage_db()
    initialize_tables(elements)
    
    print("*** Listening for packets ....\n")
    #sniff(iface = interface, prn=examine_packet, store= 0)
    
    Thread(target = sniff_arps).start()
    
