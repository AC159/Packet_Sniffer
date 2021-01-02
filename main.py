from scapy.all import *
from scapy.layers.inet import IP, ICMP
from chalky import sty, fg, bg
import argparse
from banners import print_banner
import sys
import netifaces


def main():

    print_banner()

    parser = argparse.ArgumentParser(description="Packet Sniffer")
    group = parser.add_mutually_exclusive_group()

    # Can't have all these options turned on:
    group.add_argument('--sniff_basic', action='store_true', help="Give basic information about each sniffed packet")
    group.add_argument('--sniff_detail', action='store_true', help="Give detailed information about each sniffed packet")
    group.add_argument('-p', '--ping', type=str, help="Ping domain name or IP address")
    group.add_argument('--interfaces', action='store_true', help="Show a list of detected network interfaces")

    parser.add_argument('-i', '--interface', type=str, help="Name of the wireless network adapter")
    parser.add_argument('-c', '--count', type=int, help='# of packets to sniff')

    args = parser.parse_args()

    if args.interfaces:
        print(netifaces.interfaces())

    if args.sniff_basic:

        if args.count:
            sniff(count=args.count, iface=args.interface, prn=lambda p: p.summary())
        else:
            # Display a basic summary of each captured packet:
            sniff(iface=args.interface, prn=lambda p: p.summary())

    if args.sniff_detail:

        if args.count:
            sniff(count=args.count, iface=args.interface, prn=lambda p: p.show())
        else:
            # Display a basic summary of each captured packet:
            sniff(iface=args.interface, prn=lambda p: p.show())

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

    # Display detailed information about each packet:
    sniff(iface="wlx00c0caaba31a", prn=lambda p: p.show())


if __name__ == '__main__':
    main()

