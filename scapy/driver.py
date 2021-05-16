from scapy.all import *
import argparse
from entropy_computer import Entropy_Computer

def callback(ec, packet):
    if IP in packet:
        ec.process_packet(packet)

def run(ec, pcap = None):
    if pcap is not None:
        if not os.path.exists(os.path.join(os.getcwd(), 'pcap_files', pcap)):
            print(f'Invalid input file: {pcap}. Is it in pcap_files?')
            return -1
            
        for packet in rdpcap(os.path.join(os.getcwd(), 'pcap_files', pcap)):
            callback(ec, packet)

        return 0

    else:
        sniff(filter='ip', prn=callback)

if __name__ == '__main__':
    # Get command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help = 'Input File')
    args = parser.parse_args()

    # Define entropy computer
    ec = Entropy_Computer()

    run(ec = ec, pcap = args.input)

    stats = ec.get_stats()
    for stat in stats:
        print(f'{stat}: {stats[stat].calculate_entropy()}')