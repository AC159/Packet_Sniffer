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
    group.add_argument('--ping', type=str, help="Ping domain name or IP address")
    group.add_argument('--interfaces', action='store_true', help="Show a list of detected network interfaces")
    group.add_argument('-s', '--syn', type=str, help="Check for open ports with a syn scan: provide with an ip address & --port option")
    group.add_argument('--arp', action='store_true', help="Try to discover available hosts present on the network")
    group.add_argument('--arp_poisoning', action='store_true', help="Poison victim's cache (provide --mac & --victim_ip flags")

    group_2 = parser.add_mutually_exclusive_group()

    # Cannot read & write at the same time:
    group_2.add_argument('--write', type=str, help="Write captured packets (end filename with .pcap)")
    group_2.add_argument('--read', type=str, help="Read .pcap file and display summary of each packet")

    parser.add_argument('--port', type=str, help="Port number of the IP address to scan")
    parser.add_argument('--mac', type=str, help="Your MAC address")
    parser.add_argument('--victim_ip', type=str, help="Target's IP")
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

        # todo: Add filter for TCP / ARP / ICMP packets...

        if args.write:
            # Write to pcap file:

            if args.count:
                packets = sniff(count=args.count, iface=args.interface)
                wrpcap(args.write, packets)
            else:
                # Display a basic summary of each captured packet:
                packets = sniff(iface=args.interface)
                wrpcap(args.write, packets)

        else:

            if args.count:
                sniff(count=args.count, iface=args.interface, prn=lambda p: p.summary())
            else:
                # Display a basic summary of each captured packet:
                sniff(iface=args.interface, prn=lambda p: p.summary())

    if args.sniff_detail:

        if args.count:
            sniff(count=args.count, iface=args.interface, prn=lambda p: p.show())
        else:
            # Display details of each captured packet:
            sniff(iface=args.interface, prn=lambda p: p.show())

    # Ping an IP address or domain name: (i.e. google.com) or local router 192.168.0.1:
    if args.ping:

        print(fg.cyan | "Concise response: ")
        print(sr1(IP(dst=args.ping)))

        print(fg.cyan | "Detailed response: ")
        print(sr1(IP(dst=args.ping)).show())

    if args.syn:

        if not args.port:
            print(fg.bright_red | "You must specify the --port number with the SYN option...")

        answer = sr(IP(dst=args.syn) / TCP(dport=args.port, flags='S'))
        print(answer.summary())

    if args.arp:

        answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.0.0/24"), timeout=5)
        print(chalk.bgGreen("ARP answers: "))
        answered.summary(lambda s, r: r.sprintf("%Ether.src%: %ARP.psrc%"))

    if args.read:

        packets = rdpcap(args.read)
        print(packets.summary())

    if args.arp_poisoning:

        if not args.mac or not args.victim_ip:
            print(chalk.red("Provide your MAC address & the victim's IP..."))
            sys.exit(0)

        arpcachepoison(args.mac, args.victim_ip)


if __name__ == '__main__':
    main()

