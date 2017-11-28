#!/usr/local/bin/python

from scapy.all import *     # python sniffing module
import sys

http_method=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]

def usage():
    print "./tcp_block [interface]"
    sys.exit(1)

def forward_rst(pkt):
    pkt['TCP'].flags=0b100
    print '[*]forward_rst'
    print pkt.summary()
    send(pkt)

def backward_rst(pkt):
    #pkt['TCP'].flags=0b100
    print '[*]backward_rst'
    i=pkt['IP']
    t=pkt['TCP']
    p=IP(dst=i.src,src=i.dst)/TCP(dport=t.sport,sport=t.dport,flags=0b100)
    print p.summary()
    send(p)

def backward_fin(pkt):
    print '[*]backward_fin'
    i = pkt['IP']
    t = pkt['TCP']
    p = IP(dst=i.src, src=i.dst) / TCP(dport=t.sport, sport=t.dport, flags=0b100)
    print p.summary()
    send(p)


def pkt_callback(pkt):
    #F = bin(pkt['TCP'].flags
    print pkt.summary()
    if pkt.haslayer(Raw):
        h=str(pkt.getlayer(Raw)).split('\n')[0]
        for m in http_method:
            if m in h:
                forward_rst(pkt)
                backward_fin(pkt)
                return
    forward_rst(pkt)
    backward_rst(pkt)
    return



if __name__=="__main__":
    debug=True
    if debug is False:
        try:
            interface=sys.argv[1]
        except:
            usage()
    else:
        interface="en0"
    try:
        sniff(iface=interface,prn=pkt_callback,filter="tcp",store=0)
    except KeyboardInterrupt:
        sys.exit(1)

