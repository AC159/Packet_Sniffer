from scapy.all import *
from scapy.layers.inet import IP, ICMP
from chalky import sty, fg, bg


def main():

    debug = sty.dim & fg.white
    success = fg.bright_blue & sty.bold
    error = fg.red & sty.bold
    critical = bg.red & fg.white

    # p = sr1(IP(dst="google.com") / ICMP())
    # if p:
    #     p.show()

    # packets = sniff(count=5)
    # print(packets)
    #
    # print(success | "Here are some details about the packets: ")
    # print(packets.summary())

    # Display a basic summary of each captured packet:
    sniff(iface="wlx00c0caaba31a", prn=lambda p: p.summary())

    # Display detailed information about each packet:
    sniff(iface="wlx00c0caaba31a", prn=lambda p: p.show())


if __name__ == '__main__':
    main()

