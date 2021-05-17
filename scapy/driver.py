from scapy.all import *
import argparse
from entropy_computer import Entropy_Computer

def run(ec, pcap = None, t = 10):
    def callback(packet):
        if IP in packet:
            ec.process_packet(packet)

    if pcap is not None:
        # If there is an input pcap, we run our entropy computer on that
        if not os.path.exists(os.path.join(os.getcwd(), 'pcap_files', pcap)):
            print(f'Invalid input file: {pcap}. Is it in pcap_files?')
            return -1
            
        # Reads pcap and runs 'callback' on each packet
        for packet in rdpcap(os.path.join(os.getcwd(), 'pcap_files', pcap)):
            callback(packet)
    else:
        # If there is no input pcap, we sniff with a stream of incoming packets
        sniff(filter='ip', prn=callback, timeout=t)

if __name__ == '__main__':
    # Get command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help = 'Input File')
    parser.add_argument('-t', '--timeout', help = 'Timeout Length (for sniffing)')
    args = parser.parse_args()

    # Define entropy computer
    ec = Entropy_Computer()
    
    # Pcap is either live (sniffing) or pre-recorded
    run(ec = ec, pcap = args.input, t = int(args.timeout))

    # Print out the stats obtianed
    stats = ec.get_stats()
    for stat in stats:
        print(f'{stat}: {stats[stat].calculate_entropy()}')