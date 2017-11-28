#!/usr/local/bin/python

from scapy.all import *     # python sniffing module
import sys,time

http_method=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]
cnt=0
def usage():
    print "./tcp_block [interface]"
    sys.exit(1)

def forward_rst(pkt):
    pkt['TCP'].flags=0b10100
    #pkt['TCP'].window+=1
    print '[*]forward_rst'
    print pkt.summary()
    send(pkt)

def backward_rst(pkt):
    #pkt['TCP'].flags=0b100
    print '[*]backward_rst'
    i=pkt['IP']
    t=pkt['TCP']
    p=IP(dst=i.src,src=i.dst)/TCP(dport=t.sport,sport=t.dport,flags=0b10100,window=0,ack=pkt['TCP'].ack)
    p.show()
    send(p)

def backward_fin(pkt):
    print '[*]backward_fin'
    i = pkt['IP']
    t = pkt['TCP']
    redirection='HTTP / 1.1 302 Redirect\x0d\x0aLocation: http://say2.kr\x0d\x0a\x0d\x0a'
    '''
    00000000  48 54 54 50 2f 31 2e 31  20 33 30 32 20 52 65 64   HTTP/1.1  302 Red
    00000010  69 72 65 63 74 0d 0a 4c  6f 63 61 74 69 6f 6e 3a   irect..L ocation:
    00000020  20 68 74 74 70 3a 2f 2f  77 77 77 2e 77 61 72 6e    http:// www.warn
    00000030  69 6e 67 2e 6f 72 2e 6b  72 0d 0a 0d 0a
    '''
    p = IP(dst=i.src, src=i.dst) / TCP(dport=t.sport, sport=t.dport, flags=0b10001, ack=t.seq+(i.len-0x14-t.dataofs*4)) / redirection #APF

    #p.show()
    p.show()
    send(p)


def pkt_callback(pkt):
    global cnt
    cnt=cnt+1
    if cnt==100000000:
        time.sleep(10000)
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

