from scapy.all import *
from scapy.layers.inet import IP, ICMP
from chalky import sty, fg, bg
from simple_chalk import chalk
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

    # If the user did not specify any network interface and did not specify the option to list the detected
    # interfaces, then issue a message:
    if not args.interface and not args.interfaces:
        print(chalk.magenta("Network interface was not specified..."))
        print(chalk.magenta("Run the program with the ") + chalk.green("-i / --interfaces") +
              chalk.magenta(" option to show a list of detected network interfaces..."))
        sys.exit(0)

    if args.interfaces:

        for count, interface in enumerate(netifaces.interfaces()):
            print(str(count + 1) + '. ' + interface)

        sys.exit(0)

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

    # Ping an IP address or domain name: (i.e. google.com)
    if args.ping:
        p = sr1(IP(dst=args.ping / ICMP()))
        if p:
            p.show()

    debug = sty.dim & fg.white
    success = fg.bright_blue & sty.bold
    error = fg.red & sty.bold
    critical = bg.red & fg.white

    # packets = sniff(count=5)
    # print(packets)
    #
    # print(success | "Here are some details about the packets: ")
    # print(packets.summary())

    # Display detailed information about each packet:
    # sniff(iface="wlx00c0caaba31a", prn=lambda p: p.show())


if __name__ == '__main__':
    main()

