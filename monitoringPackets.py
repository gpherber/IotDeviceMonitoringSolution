import pyshark
import time
import ipaddress

def get_packets(networkInterface, numberOfPackets):
    # define capture object
    capture = pyshark.LiveCapture(interface=networkInterface)
    ## listen for number of packets defined in the configuration filtered to only include traffic originating at a private ip
    print(f"listening for {numberOfPackets} packets on {networkInterface}")
    packets = []
    for packet in capture.sniff_continuously(packet_count=numberOfPackets):
        # get timestamp
        localtime = time.asctime(time.localtime(time.time()))
        # adjusted output
        try:
            protocol = packet.transport_layer
        # get packet content
            src_addr = packet.ip.src # source address
            if ipaddress.ip_address(src_addr).is_private == True:
                dstport = packet[protocol].dstport
                if int(dstport) < 10000:            # source private
                    packets.append(packet)
                    print (" %s %s IP %s:%s <-> %s:%s (%s)" % (packet.eth.src, localtime, src_addr, packet[protocol].srcport, packet.ip.dst, dstport, protocol))
        except AttributeError as e:
            pass
    return packets
